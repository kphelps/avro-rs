//! Logic for parsing and interacting with schemas in Avro format.
use std::borrow::Cow;
use std::collections::HashMap;
use std::fmt;

use digest::Digest;
use failure::Error;
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use serde_json::{self, Map, Value};

use crate::types;
use crate::util::MapHelper;

/// Describes errors happened while parsing Avro schemas.
#[derive(Fail, Debug)]
#[fail(display = "Failed to parse schema: {}", _0)]
pub struct ParseSchemaError(String);

impl ParseSchemaError {
    pub fn new<S>(msg: S) -> ParseSchemaError
    where
        S: Into<String>,
    {
        ParseSchemaError(msg.into())
    }
}

/// Represents an Avro schema fingerprint
/// More information about Avro schema fingerprints can be found in the
/// [Avro Schema Fingerprint documentation](https://avro.apache.org/docs/current/spec.html#schema_fingerprints)
pub struct SchemaFingerprint {
    pub bytes: Vec<u8>,
}

impl fmt::Display for SchemaFingerprint {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            self.bytes
                .iter()
                .map(|byte| format!("{:02x}", byte))
                .collect::<Vec<String>>()
                .join("")
        )
    }
}

pub type SchemaTypes = HashMap<String, Schema>;

#[derive(Clone, Debug, PartialEq)]
pub struct FullSchema {
    pub schema: Schema,
    pub types: SchemaTypes,
}

pub trait SchemaIter<'a> {
    fn schema(&self) -> &'a Schema;
    fn types(&self) -> &'a SchemaTypes;

    fn as_full_schema(&self) -> FullSchema {
        FullSchema {
            schema: self.schema().clone(),
            types: self.types().clone(),
        }
    }

    fn kind(&self) -> SchemaKind {
        self.resolve_reference().into()
    }

    fn fullname(&self) -> Option<String> {
        let fullname = match self.resolve_reference() {
            Schema::Record(ref schema) => schema.name.fullname(None),
            Schema::Fixed { ref name, .. } => name.fullname(None),
            Schema::Enum { ref name, .. } => name.fullname(None),
            _ => return None,
        };
        Some(fullname)
    }

    fn build_iter(&self, schema: &'a Schema) -> SchemaRef<'a> {
        SchemaRef {
            schema,
            types: self.types(),
        }
    }

    fn resolve_reference(&self) -> &'a Schema {
        match self.schema() {
            Schema::Reference(name) => {
                self.types().get(&name.fullname(None))
                    .expect("invalid reference")
            },
            schema => schema,
        }
    }

    fn fixed_size(&self) -> usize {
        let resolved = self.resolve_reference();
        if let Schema::Fixed{ size, .. } = resolved {
            *size
        } else {
            unimplemented!();
        }
    }

    fn array_schema(&self) -> SchemaRef<'a> {
        let resolved = self.resolve_reference();
        if let Schema::Array(inner) = resolved {
            self.build_iter(inner)
        } else {
            unimplemented!();
        }
    }

    fn map_schema(&self) -> SchemaRef<'a> {
        let resolved = self.resolve_reference();
        if let Schema::Map(inner) = resolved {
            self.build_iter(inner)
        } else {
            unimplemented!();
        }
    }

    fn union_schema(&self) -> UnionSchemaRef<'a> {
        let resolved = self.resolve_reference();
        if let Schema::Union(inner) = resolved {
            UnionSchemaRef {
                union: inner,
                types: &self.types(),
            }
        } else {
            unimplemented!();
        }
    }

    fn record_schema(&self) -> RecordSchemaRef<'a> {
        let resolved = self.resolve_reference();
        if let Schema::Record(inner) = resolved {
            RecordSchemaRef {
                schema: inner,
                types: &self.types(),
            }
        } else {
            unimplemented!();
        }
    }
}

impl<'a> SchemaIter<'a> for &'a FullSchema {
    fn schema(&self) -> &'a Schema {
        &self.schema
    }

    fn types(&self) -> &'a SchemaTypes {
        &self.types
    }
}

#[derive(Clone, Copy)]
pub struct SchemaRef<'a> {
    schema: &'a Schema,
    types: &'a SchemaTypes,
}

impl<'a> SchemaIter<'a> for SchemaRef<'a> {
    fn schema(&self) -> &'a Schema {
        &self.schema
    }

    fn types(&self) -> &'a SchemaTypes {
        self.types
    }
}

pub struct RecordSchemaRef<'a> {
    schema: &'a RecordSchema,
    types: &'a SchemaTypes,
}

impl<'a> RecordSchemaRef<'a> {
    pub fn fields(&self) -> Vec<RecordFieldRef<'a>> {
        self.schema.fields
            .iter()
            .map(|field| RecordFieldRef { field, types: self.types })
            .collect()
    }

    pub fn name(&self) -> &Name {
        &self.schema.name
    }

    pub fn lookup(&self) -> &HashMap<String, usize> {
        &self.schema.lookup
    }

    pub fn new_record(&'a self) -> types::Record<'a> {
        types::Record::from_ref(&self)
    }
}

pub struct RecordFieldRef<'a> {
    field: &'a RecordField,
    types: &'a SchemaTypes,
}

impl<'a> RecordFieldRef<'a> {
    pub fn name(&self) -> &str {
        &self.field.name
    }

    pub fn schema(&self) -> SchemaRef<'a> {
        SchemaRef {
            schema: &self.field.schema,
            types: self.types,
        }
    }
}

pub struct UnionSchemaRef<'a> {
    union: &'a UnionSchema,
    types: &'a SchemaTypes,
}

impl<'a> UnionSchemaRef<'a> {
    pub fn variants(&self) -> Vec<SchemaRef<'a>> {
        self.union.variants()
            .iter()
            .map(|schema| SchemaRef { schema, types: self.types })
            .collect()
    }

    pub fn union_ref_map(&self) -> HashMap<UnionRef, usize> {
        let mut map = HashMap::new();
        self.union.variants().iter().enumerate().for_each(|(i, schema)| {
            map.insert(UnionRef::from_schema(schema), i);
        });
        map
    }
}

/// Represents any valid Avro schema
/// More information about Avro schemas can be found in the
/// [Avro Specification](https://avro.apache.org/docs/current/spec.html#schemas)
#[derive(Clone, Debug, PartialEq)]
pub enum Schema {
    /// A `null` Avro schema.
    Null,
    /// A `boolean` Avro schema.
    Boolean,
    /// An `int` Avro schema.
    Int,
    /// A `long` Avro schema.
    Long,
    /// A `float` Avro schema.
    Float,
    /// A `double` Avro schema.
    Double,
    /// A `bytes` Avro schema.
    /// `Bytes` represents a sequence of 8-bit unsigned bytes.
    Bytes,
    /// A `string` Avro schema.
    /// `String` represents a unicode character sequence.
    String,
    /// A `array` Avro schema. Avro arrays are required to have the same type for each element.
    /// This variant holds the `Schema` for the array element type.
    Array(Box<Schema>),
    /// A `map` Avro schema.
    /// `Map` holds a pointer to the `Schema` of its values, which must all be the same schema.
    /// `Map` keys are assumed to be `string`.
    Map(Box<Schema>),
    /// A `union` Avro schema.
    Union(UnionSchema),
    /// A `record` Avro schema.
    ///
    /// The `lookup` table maps field names to their position in the `Vec`
    /// of `fields`.
    Record(RecordSchema),
    /// An `enum` Avro schema.
    Enum {
        name: Name,
        doc: Documentation,
        symbols: Vec<String>,
    },
    /// A `fixed` Avro schema.
    Fixed { name: Name, size: usize },
    Reference(Name),
}

#[derive(Clone, Debug, PartialEq)]
pub struct RecordSchema {
    pub name: Name,
    pub doc: Documentation,
    pub fields: Vec<RecordField>,
    pub lookup: HashMap<String, usize>,
}

impl RecordSchema {
    pub fn new(
        name: Name,
        doc: Documentation,
        fields: Vec<RecordField>,
        lookup: HashMap<String, usize>,
    ) -> Self {
        Self {
            name,
            doc,
            fields,
            lookup,
        }
    }
}

/// This type is used to simplify enum variant comparison between `Schema` and `types::Value`.
/// It may have utility as part of the public API, but defining as `pub(crate)` for now.
///
/// **NOTE** This type was introduced due to a limitation of `mem::discriminant` requiring a _value_
/// be constructed in order to get the discriminant, which makes it difficult to implement a
/// function that maps from `Discriminant<Schema> -> Discriminant<Value>`. Conversion into this
/// intermediate type should be especially fast, as the number of enum variants is small, which
/// _should_ compile into a jump-table for the conversion.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum SchemaKind {
    Null,
    Boolean,
    Int,
    Long,
    Float,
    Double,
    Bytes,
    String,
    Array,
    Map,
    Union,
    Record,
    Enum,
    Fixed,
}

impl<'a> From<&'a Schema> for SchemaKind {
    #[inline(always)]
    fn from(schema: &'a Schema) -> SchemaKind {
        // NOTE: I _believe_ this will always be fast as it should convert into a jump table.
        match schema {
            Schema::Null => SchemaKind::Null,
            Schema::Boolean => SchemaKind::Boolean,
            Schema::Int => SchemaKind::Int,
            Schema::Long => SchemaKind::Long,
            Schema::Float => SchemaKind::Float,
            Schema::Double => SchemaKind::Double,
            Schema::Bytes => SchemaKind::Bytes,
            Schema::String => SchemaKind::String,
            Schema::Array(_) => SchemaKind::Array,
            Schema::Map(_) => SchemaKind::Map,
            Schema::Union(_) => SchemaKind::Union,
            Schema::Record(_) => SchemaKind::Record,
            Schema::Enum { .. } => SchemaKind::Enum,
            Schema::Fixed { .. } => SchemaKind::Fixed,
            Schema::Reference(_) => SchemaKind::Record,
        }
    }
}

impl<'a> From<&'a types::Value> for SchemaKind {
    #[inline(always)]
    fn from(value: &'a types::Value) -> SchemaKind {
        match value {
            types::Value::Null => SchemaKind::Null,
            types::Value::Boolean(_) => SchemaKind::Boolean,
            types::Value::Int(_) => SchemaKind::Int,
            types::Value::Long(_) => SchemaKind::Long,
            types::Value::Float(_) => SchemaKind::Float,
            types::Value::Double(_) => SchemaKind::Double,
            types::Value::Bytes(_) => SchemaKind::Bytes,
            types::Value::String(_) => SchemaKind::String,
            types::Value::Array(_) => SchemaKind::Array,
            types::Value::Map(_) => SchemaKind::Map,
            types::Value::Union(_, _) => SchemaKind::Union,
            types::Value::Record(_) => SchemaKind::Record,
            types::Value::Enum(_, _) => SchemaKind::Enum,
            types::Value::Fixed(_, _) => SchemaKind::Fixed,
        }
    }
}

/// Represents names for `record`, `enum` and `fixed` Avro schemas.
///
/// Each of these `Schema`s have a `fullname` composed of two parts:
///   * a name
///   * a namespace
///
/// `aliases` can also be defined, to facilitate schema evolution.
///
/// More information about schema names can be found in the
/// [Avro specification](https://avro.apache.org/docs/current/spec.html#names)
#[derive(Clone, Debug, PartialEq)]
pub struct Name {
    pub name: String,
    pub namespace: Option<String>,
    pub aliases: Option<Vec<String>>,
}

/// Represents documentation for complex Avro schemas.
pub type Documentation = Option<String>;

impl Name {
    /// Create a new `Name`.
    /// No `namespace` nor `aliases` will be defined.
    pub fn new(name: &str) -> Name {
        Name {
            name: name.to_owned(),
            namespace: None,
            aliases: None,
        }
    }

    /// Parse a `serde_json::Value` into a `Name`.
    fn parse(complex: &Map<String, Value>) -> Result<Self, Error> {
        let name = complex
            .name()
            .ok_or_else(|| ParseSchemaError::new("No `name` field"))?;

        let namespace = complex.string("namespace");

        let aliases: Option<Vec<String>> = complex
            .get("aliases")
            .and_then(|aliases| aliases.as_array())
            .and_then(|aliases| {
                aliases
                    .iter()
                    .map(|alias| alias.as_str())
                    .map(|alias| alias.map(|a| a.to_string()))
                    .collect::<Option<_>>()
            });

        Ok(Name {
            name,
            namespace,
            aliases,
        })
    }

    /// Return the `fullname` of this `Name`
    ///
    /// More information about fullnames can be found in the
    /// [Avro specification](https://avro.apache.org/docs/current/spec.html#names)
    pub fn fullname(&self, default_namespace: Option<&str>) -> String {
        if self.name.contains('.') {
            self.name.clone()
        } else {
            let namespace = self
                .namespace
                .as_ref()
                .map(|s| s.as_ref())
                .or(default_namespace);

            match namespace {
                Some(ref namespace) => format!("{}.{}", namespace, self.name),
                None => self.name.clone(),
            }
        }
    }
}

/// Represents a `field` in a `record` Avro schema.
#[derive(Clone, Debug, PartialEq)]
pub struct RecordField {
    /// Name of the field.
    pub name: String,
    /// Documentation of the field.
    pub doc: Documentation,
    /// Default value of the field.
    /// This value will be used when reading Avro datum if schema resolution
    /// is enabled.
    pub default: Option<Value>,
    /// Schema of the field.
    pub schema: Schema,
    /// Order of the field.
    ///
    /// **NOTE** This currently has no effect.
    pub order: RecordFieldOrder,
    /// Position of the field in the list of `field` of its parent `Schema`
    pub position: usize,
}

/// Represents any valid order for a `field` in a `record` Avro schema.
#[derive(Clone, Debug, PartialEq)]
pub enum RecordFieldOrder {
    Ascending,
    Descending,
    Ignore,
}

impl RecordField {
    /// Parse a `serde_json::Value` into a `RecordField`.
    fn parse(field: &Map<String, Value>, position: usize, context: &mut SchemaParseContext) -> Result<Self, Error> {
        let name = field
            .name()
            .ok_or_else(|| ParseSchemaError::new("No `name` in record field"))?;

        let schema = field
            .get("type")
            .ok_or_else(|| ParseSchemaError::new("No `type` in record field").into())
            .and_then(|type_| Schema::parse_with_context(type_, context))?;

        let default = field.get("default").cloned();

        let order = field
            .get("order")
            .and_then(|order| order.as_str())
            .and_then(|order| match order {
                "ascending" => Some(RecordFieldOrder::Ascending),
                "descending" => Some(RecordFieldOrder::Descending),
                "ignore" => Some(RecordFieldOrder::Ignore),
                _ => None,
            }).unwrap_or_else(|| RecordFieldOrder::Ascending);

        Ok(RecordField {
            name,
            doc: field.doc(),
            default,
            schema,
            order,
            position,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct UnionRef {
    inner: UnionRefInner,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum UnionRefInner {
    Primitive(SchemaKind),
    Named(String),
}

impl UnionRef {
    pub(crate) fn primitive(kind: SchemaKind) -> Self {
        UnionRef {
            inner: UnionRefInner::Primitive(kind),
        }
    }

    pub fn named(name: &Name) -> Self {
        Self::from_fullname(name.fullname(None))
    }

    pub fn from_fullname(name: String) -> Self {
        UnionRef {
            inner: UnionRefInner::Named(name)
        }
    }

    pub fn from_schema(schema: &Schema) -> Self {
        if let Some(ref name) = schema.name() {
            Self::named(name)
        } else {
            Self::primitive(SchemaKind::from(schema))
        }
    }

    pub fn from_value(value: &crate::types::Value) -> Self {
        UnionRef::primitive(SchemaKind::from(value))
    }
}

#[derive(Debug, Clone)]
pub struct UnionSchema {
    schemas: Vec<Schema>,
    // Used to ensure uniqueness of schema inputs, and provide constant time finding of the
    // schema index given a value.
    // **NOTE** that this approach does not work for named types, and will have to be modified
    // to support that. A simple solution is to also keep a mapping of the names used.
    variant_index: HashMap<UnionRef, usize>,
}

impl UnionSchema {
    pub(crate) fn new(schemas: Vec<Schema>) -> Result<Self, Error> {
        let mut vindex = HashMap::new();
        for (i, schema) in schemas.iter().enumerate() {
            if let Schema::Union(_) = schema {
                Err(ParseSchemaError::new(
                    "Unions may not directly contain a union",
                ))?;
            }
            let union_ref = UnionRef::from_schema(schema);
            if vindex.insert(union_ref, i).is_some() {
                Err(ParseSchemaError::new(
                    "Unions cannot contain duplicate types",
                ))?;
            }
        }
        Ok(UnionSchema {
            schemas,
            variant_index: vindex,
        })
    }

    /// Returns a slice to all variants of this schema.
    pub fn variants(&self) -> &[Schema] {
        &self.schemas
    }

    /// Returns true if the first variant of this `UnionSchema` is `Null`.
    pub fn is_nullable(&self) -> bool {
        !self.schemas.is_empty() && self.schemas[0] == Schema::Null
    }

    /// Optionally returns a reference to the schema matched by this value, as well as its position
    /// within this enum.
    pub fn find_schema(&self, value: &crate::types::Value) -> Option<(usize, &Schema)> {
        let union_ref = UnionRef::from_value(value);
        self.find_ref(&union_ref)
    }

    pub fn find_ref(&self, union_ref: &UnionRef) -> Option<(usize, &Schema)> {
        self.variant_index
            .get(union_ref)
            .cloned()
            .map(|i| (i, &self.schemas[i]))
    }
}

// No need to compare variant_index, it is derivative of schemas.
impl PartialEq for UnionSchema {
    fn eq(&self, other: &UnionSchema) -> bool {
        self.schemas.eq(&other.schemas)
    }
}

#[derive(Debug)]
struct SchemaParseContext {
    namespace_scopes: Vec<String>,
    type_registry: HashMap<String, Option<Schema>>,
}

impl SchemaParseContext {
    fn new() -> Self {
        Self {
            namespace_scopes: Vec::new(),
            type_registry: HashMap::new(),
        }
    }

    fn declare_type(&mut self, name: &Name) {
        if let Some(ref namespace) = name.namespace {
            self.namespace_scopes.push(namespace.clone());
        }
        self.type_registry.insert(self.resolve_name(name), None);
    }

    fn has_type(&self, name: &Name) -> bool {
        self.type_registry.contains_key(&self.resolve_name(name))
    }

    fn register_type(&mut self, name: &Name, schema: Schema) {
        self.type_registry.insert(self.resolve_name(name), Some(schema));
        if let Some(_) = name.namespace {
            self.namespace_scopes.pop();
        }
    }

    // fn lookup_type(&self, name: &Name) -> Option<&Schema> {
    //     self.type_registry
    //         .get(&self.resolve_name(name))
    //         .and_then(|x| x.as_ref())
    // }

    fn resolve_name(&self, name: &Name) -> String {
        name.fullname(self.current_namespace())
    }

    fn current_namespace(&self) -> Option<&str> {
        self.namespace_scopes.last().map(String::as_str)
    }

    fn into_types(self) -> SchemaTypes {
        self.type_registry.into_iter().map(|(key, value)| {
            (key, value.unwrap())
        }).collect()
    }
}

impl Schema {
    /// Create a `Schema` from a string representing a JSON Avro schema.
    pub fn parse_str(input: &str) -> Result<FullSchema, Error> {
        let value = serde_json::from_str(input)?;
        Self::parse(&value)
    }

    /// Create a `Schema` from a `serde_json::Value` representing a JSON Avro
    /// schema.
    pub fn parse(value: &Value) -> Result<FullSchema, Error> {
        let mut context = SchemaParseContext::new();
        let schema = Self::parse_with_context(value, &mut context)?;
        Ok(FullSchema {
            schema,
            types: context.into_types(),
        })
    }

    fn parse_with_context(value: &Value, context: &mut SchemaParseContext) -> Result<Self, Error> {
        match *value {
            Value::String(ref t) => Schema::parse_primitive(t.as_str(), context),
            Value::Object(ref data) => Schema::parse_complex(data, context),
            Value::Array(ref data) => Schema::parse_union(data, context),
            _ => Err(ParseSchemaError::new("Must be a JSON string, object or array").into()),
        }
    }

    pub fn as_full_schema(self) -> FullSchema {
        FullSchema {
            schema: self,
            types: SchemaTypes::new(),
        }
    }

    /// Converts `self` into its [Parsing Canonical Form].
    ///
    /// [Parsing Canonical Form]:
    /// https://avro.apache.org/docs/1.8.2/spec.html#Parsing+Canonical+Form+for+Schemas
    pub fn canonical_form(&self) -> String {
        let json = serde_json::to_value(self).unwrap();
        parsing_canonical_form(&json)
    }

    /// Generate [fingerprint] of Schema's [Parsing Canonical Form].
    ///
    /// [Parsing Canonical Form]:
    /// https://avro.apache.org/docs/1.8.2/spec.html#Parsing+Canonical+Form+for+Schemas
    /// [fingerprint]:
    /// https://avro.apache.org/docs/current/spec.html#schema_fingerprints
    pub fn fingerprint<D: Digest>(&self) -> SchemaFingerprint {
        let mut d = D::new();
        d.input(self.canonical_form());
        SchemaFingerprint {
            bytes: d.result().to_vec(),
        }
    }

    /// Parse a `serde_json::Value` representing a primitive Avro type into a
    /// `Schema`.
    fn parse_primitive(primitive: &str, context: &mut SchemaParseContext) -> Result<Self, Error> {
        match primitive {
            "null" => Ok(Schema::Null),
            "boolean" => Ok(Schema::Boolean),
            "int" => Ok(Schema::Int),
            "long" => Ok(Schema::Long),
            "double" => Ok(Schema::Double),
            "float" => Ok(Schema::Float),
            "bytes" => Ok(Schema::Bytes),
            "string" => Ok(Schema::String),
            other => Self::parse_reference(other, context),
        }
    }

    fn parse_reference(reference: &str, context: &mut SchemaParseContext) -> Result<Self, Error> {
        let name = Name::new(reference);
        if context.has_type(&name) {
            Ok(Schema::Reference(name))
        } else {
            Err(ParseSchemaError::new(format!("Unknown type: {}", reference)).into())
        }
    }

    /// Parse a `serde_json::Value` representing a complex Avro type into a
    /// `Schema`.
    ///
    /// Avro supports "recursive" definition of types.
    /// e.g: {"type": {"type": "string"}}
    fn parse_complex(complex: &Map<String, Value>, context: &mut SchemaParseContext) -> Result<Self, Error> {
        match complex.get("type") {
            Some(&Value::String(ref t)) => match t.as_str() {
                "array" => Schema::parse_array(complex, context),
                "map" => Schema::parse_map(complex, context),
                "record" | "enum" | "fixed" => Schema::parse_named(complex, context),
                other => Schema::parse_primitive(other, context),
            },
            Some(&Value::Object(ref data)) => match data.get("type") {
                Some(ref value) => Schema::parse_with_context(value, context),
                None => Err(
                    ParseSchemaError::new(format!("Unknown complex type: {:?}", complex)).into(),
                ),
            },
            _ => Err(ParseSchemaError::new("No `type` in complex type").into()),
        }
    }

    fn parse_named(complex: &Map<String, Value>, context: &mut SchemaParseContext) -> Result<Self, Error> {
        let name = Name::parse(complex)?;
        context.declare_type(&name);

        let schema = match complex.get("type") {
            Some(&Value::String(ref t)) => match t.as_str() {
                "record" => Schema::parse_record(complex, context),
                "enum" => Schema::parse_enum(complex),
                "fixed" => Schema::parse_fixed(complex),
                _ => panic!("parse_named got wrong type"),
            },
            _ => panic!("parse_named got wrong type"),
        }?;
        context.register_type(&name, schema.clone());
        Ok(schema)
    }

    /// Parse a `serde_json::Value` representing a Avro record type into a
    /// `Schema`.
    fn parse_record(complex: &Map<String, Value>, context: &mut SchemaParseContext) -> Result<Self, Error> {
        let name = Name::parse(complex)?;

        let mut lookup = HashMap::new();

        let fields: Vec<RecordField> = complex
            .get("fields")
            .and_then(|fields| fields.as_array())
            .ok_or_else(|| ParseSchemaError::new("No `fields` in record").into())
            .and_then(|fields| {
                fields
                    .iter()
                    .filter_map(|field| field.as_object())
                    .enumerate()
                    .map(|(position, field)| RecordField::parse(field, position, context))
                    .collect::<Result<_, _>>()
            })?;

        for field in &fields {
            lookup.insert(field.name.clone(), field.position);
        }

        let record_schema = RecordSchema::new(
            name,
            complex.doc(),
            fields,
            lookup,
        );
        Ok(Schema::Record(record_schema))
    }

    /// Parse a `serde_json::Value` representing a Avro enum type into a
    /// `Schema`.
    fn parse_enum(complex: &Map<String, Value>) -> Result<Self, Error> {
        let name = Name::parse(complex)?;

        let symbols = complex
            .get("symbols")
            .and_then(|v| v.as_array())
            .ok_or_else(|| ParseSchemaError::new("No `symbols` field in enum"))
            .and_then(|symbols| {
                symbols
                    .iter()
                    .map(|symbol| symbol.as_str().map(|s| s.to_string()))
                    .collect::<Option<_>>()
                    .ok_or_else(|| ParseSchemaError::new("Unable to parse `symbols` in enum"))
            })?;

        Ok(Schema::Enum {
            name,
            doc: complex.doc(),
            symbols,
        })
    }

    /// Parse a `serde_json::Value` representing a Avro array type into a
    /// `Schema`.
    fn parse_array(complex: &Map<String, Value>, context: &mut SchemaParseContext) -> Result<Self, Error> {
        complex
            .get("items")
            .ok_or_else(|| ParseSchemaError::new("No `items` in array").into())
            .and_then(|items| Schema::parse_with_context(items, context))
            .map(|schema| Schema::Array(Box::new(schema)))
    }

    /// Parse a `serde_json::Value` representing a Avro map type into a
    /// `Schema`.
    fn parse_map(complex: &Map<String, Value>, context: &mut SchemaParseContext) -> Result<Self, Error> {
        complex
            .get("values")
            .ok_or_else(|| ParseSchemaError::new("No `values` in map").into())
            .and_then(|items| Schema::parse_with_context(items, context))
            .map(|schema| Schema::Map(Box::new(schema)))
    }

    /// Parse a `serde_json::Value` representing a Avro union type into a
    /// `Schema`.
    fn parse_union(items: &[Value], context: &mut SchemaParseContext) -> Result<Self, Error> {
        items
            .iter()
            .map(|item| Schema::parse_with_context(item, context))
            .collect::<Result<Vec<_>, _>>()
            .and_then(|schemas| Ok(Schema::Union(UnionSchema::new(schemas)?)))
    }

    /// Parse a `serde_json::Value` representing a Avro fixed type into a
    /// `Schema`.
    fn parse_fixed(complex: &Map<String, Value>) -> Result<Self, Error> {
        let name = Name::parse(complex)?;

        let size = complex
            .get("size")
            .and_then(|v| v.as_i64())
            .ok_or_else(|| ParseSchemaError::new("No `size` in fixed"))?;

        Ok(Schema::Fixed {
            name,
            size: size as usize,
        })
    }

    fn name(&self) -> Option<&Name> {
        match *self {
            Schema::Record(ref schema) => Some(&schema.name),
            Schema::Enum { ref name, .. } => Some(name),
            Schema::Fixed { ref name, .. } => Some(name),
            Schema::Reference(ref name) => Some(name),
            _ => None
        }
    }
}

impl Serialize for Schema {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match *self {
            Schema::Null => serializer.serialize_str("null"),
            Schema::Boolean => serializer.serialize_str("boolean"),
            Schema::Int => serializer.serialize_str("int"),
            Schema::Long => serializer.serialize_str("long"),
            Schema::Float => serializer.serialize_str("float"),
            Schema::Double => serializer.serialize_str("double"),
            Schema::Bytes => serializer.serialize_str("bytes"),
            Schema::String => serializer.serialize_str("string"),
            Schema::Array(ref inner) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("type", "array")?;
                map.serialize_entry("items", &*inner.clone())?;
                map.end()
            },
            Schema::Map(ref inner) => {
                let mut map = serializer.serialize_map(Some(2))?;
                map.serialize_entry("type", "map")?;
                map.serialize_entry("values", &*inner.clone())?;
                map.end()
            },
            Schema::Union(ref inner) => {
                let variants = inner.variants();
                let mut seq = serializer.serialize_seq(Some(variants.len()))?;
                for v in variants {
                    seq.serialize_element(v)?;
                }
                seq.end()
            },
            Schema::Record(ref schema) => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("type", "record")?;
                if let Some(ref n) = schema.name.namespace {
                    map.serialize_entry("namespace", n)?;
                }
                map.serialize_entry("name", &schema.name.name)?;
                if let Some(ref docstr) = schema.doc {
                    map.serialize_entry("doc", docstr)?;
                }
                if let Some(ref aliases) = schema.name.aliases {
                    map.serialize_entry("aliases", aliases)?;
                }
                map.serialize_entry("fields", &schema.fields)?;
                map.end()
            },
            Schema::Enum {
                ref name,
                ref symbols,
                ..
            } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("type", "enum")?;
                map.serialize_entry("name", &name.name)?;
                map.serialize_entry("symbols", symbols)?;
                map.end()
            },
            Schema::Fixed { ref name, ref size } => {
                let mut map = serializer.serialize_map(None)?;
                map.serialize_entry("type", "fixed")?;
                map.serialize_entry("name", &name.name)?;
                map.serialize_entry("size", size)?;
                map.end()
            },
            Schema::Reference(ref name) => serializer.serialize_str(&name.name),
        }
    }
}

impl Serialize for RecordField {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut map = serializer.serialize_map(None)?;
        map.serialize_entry("name", &self.name)?;
        map.serialize_entry("type", &self.schema)?;

        if let Some(ref default) = self.default {
            map.serialize_entry("default", default)?;
        }

        map.end()
    }
}

/// Parses a **valid** avro schema into the Parsing Canonical Form.
/// https://avro.apache.org/docs/1.8.2/spec.html#Parsing+Canonical+Form+for+Schemas
fn parsing_canonical_form(schema: &serde_json::Value) -> String {
    match schema {
        serde_json::Value::Object(map) => pcf_map(map),
        serde_json::Value::String(s) => pcf_string(s),
        serde_json::Value::Array(v) => pcf_array(v),
        _ => unreachable!(),
    }
}

fn pcf_map(schema: &Map<String, serde_json::Value>) -> String {
    // Look for the namespace variant up front.
    let ns = schema.get("namespace").and_then(|v| v.as_str());
    let mut fields = Vec::new();
    for (k, v) in schema {
        // Reduce primitive types to their simple form. ([PRIMITIVE] rule)
        if schema.len() == 1 && k == "type" {
            // Invariant: function is only callable from a valid schema, so this is acceptable.
            if let serde_json::Value::String(s) = v {
                return pcf_string(s)
            }
        }

        // Strip out unused fields ([STRIP] rule)
        if field_ordering_position(k).is_none() {
            continue
        }

        // Fully qualify the name, if it isn't already ([FULLNAMES] rule).
        if k == "name" {
            // Invariant: Only valid schemas. Must be a string.
            let name = v.as_str().unwrap();
            let n = match ns {
                Some(namespace) if !name.contains('.') => {
                    Cow::Owned(format!("{}.{}", namespace, name))
                },
                _ => Cow::Borrowed(name),
            };

            fields.push((k, format!("{}:{}", pcf_string(k), pcf_string(&*n))));
            continue
        }

        // Strip off quotes surrounding "size" type, if they exist ([INTEGERS] rule).
        if k == "size" {
            let i = match v.as_str() {
                Some(s) => s.parse::<i64>().expect("Only valid schemas are accepted!"),
                None => v.as_i64().unwrap(),
            };
            fields.push((k, format!("{}:{}", pcf_string(k), i)));
            continue
        }

        // For anything else, recursively process the result.
        fields.push((
            k,
            format!("{}:{}", pcf_string(k), parsing_canonical_form(v)),
        ));
    }

    // Sort the fields by their canonical ordering ([ORDER] rule).
    fields.sort_unstable_by_key(|(k, _)| field_ordering_position(k).unwrap());
    let inter = fields
        .into_iter()
        .map(|(_, v)| v)
        .collect::<Vec<_>>()
        .join(",");
    format!("{{{}}}", inter)
}

fn pcf_array(arr: &[serde_json::Value]) -> String {
    let inter = arr
        .iter()
        .map(parsing_canonical_form)
        .collect::<Vec<String>>()
        .join(",");
    format!("[{}]", inter)
}

fn pcf_string(s: &str) -> String {
    format!("\"{}\"", s)
}

// Used to define the ordering and inclusion of fields.
fn field_ordering_position(field: &str) -> Option<usize> {
    let v = match field {
        "name" => 1,
        "type" => 2,
        "fields" => 3,
        "symbols" => 4,
        "items" => 5,
        "values" => 6,
        "size" => 7,
        _ => return None,
    };

    Some(v)
}

#[cfg(test)]
mod tests {
    extern crate md5;
    extern crate sha2;

    use super::*;

    #[test]
    fn test_invalid_schema() {
        assert!(Schema::parse_str("invalid").is_err());
    }

    #[test]
    fn test_primitive_schema() {
        assert_eq!(Schema::Null, Schema::parse_str("\"null\"").unwrap().schema);
        assert_eq!(Schema::Int, Schema::parse_str("\"int\"").unwrap().schema);
        assert_eq!(Schema::Double, Schema::parse_str("\"double\"").unwrap().schema);
    }

    #[test]
    fn test_array_schema() {
        let schema = Schema::parse_str(r#"{"type": "array", "items": "string"}"#).unwrap().schema;
        assert_eq!(Schema::Array(Box::new(Schema::String)), schema);
    }

    #[test]
    fn test_map_schema() {
        let schema = Schema::parse_str(r#"{"type": "map", "values": "double"}"#).unwrap().schema;
        assert_eq!(Schema::Map(Box::new(Schema::Double)), schema);
    }

    #[test]
    fn test_union_schema() {
        let schema = Schema::parse_str(r#"["null", "int"]"#).unwrap().schema;
        assert_eq!(
            Schema::Union(UnionSchema::new(vec![Schema::Null, Schema::Int]).unwrap()),
            schema
        );
    }

    #[test]
    fn test_union_unsupported_schema() {
        let schema = Schema::parse_str(r#"["null", ["null", "int"], "string"]"#);
        assert!(schema.is_err());
    }

    #[test]
    fn test_multi_union_schema() {
        let schema = Schema::parse_str(r#"["null", "int", "float", "string", "bytes"]"#);
        assert!(schema.is_ok());
        let schema = schema.unwrap().schema;
        assert_eq!(SchemaKind::from(&schema), SchemaKind::Union);
        let union_schema = match schema {
            Schema::Union(u) => u,
            _ => unreachable!(),
        };
        assert_eq!(union_schema.variants().len(), 5);
        let mut variants = union_schema.variants().iter();
        assert_eq!(SchemaKind::from(variants.next().unwrap()), SchemaKind::Null);
        assert_eq!(SchemaKind::from(variants.next().unwrap()), SchemaKind::Int);
        assert_eq!(
            SchemaKind::from(variants.next().unwrap()),
            SchemaKind::Float
        );
        assert_eq!(
            SchemaKind::from(variants.next().unwrap()),
            SchemaKind::String
        );
        assert_eq!(
            SchemaKind::from(variants.next().unwrap()),
            SchemaKind::Bytes
        );
        assert_eq!(variants.next(), None);
    }

    #[test]
    fn test_record_schema() {
        let schema = Schema::parse_str(
            r#"
            {
                "type": "record",
                "name": "test",
                "fields": [
                    {"name": "a", "type": "long", "default": 42},
                    {"name": "b", "type": "string"}
                ]
            }
        "#,
        ).unwrap().schema;

        let mut lookup = HashMap::new();
        lookup.insert("a".to_owned(), 0);
        lookup.insert("b".to_owned(), 1);

        let record_schema = RecordSchema::new(
            Name::new("test"),
            None,
            vec![
                RecordField {
                    name: "a".to_string(),
                    doc: None,
                    default: Some(Value::Number(42i64.into())),
                    schema: Schema::Long,
                    order: RecordFieldOrder::Ascending,
                    position: 0,
                },
                RecordField {
                    name: "b".to_string(),
                    doc: None,
                    default: None,
                    schema: Schema::String,
                    order: RecordFieldOrder::Ascending,
                    position: 1,
                },
            ],
            lookup,
        );
        let expected = Schema::Record(record_schema);

        assert_eq!(expected, schema);
    }

    #[test]
    fn test_enum_schema() {
        let schema = Schema::parse_str(
            r#"{"type": "enum", "name": "Suit", "symbols": ["diamonds", "spades", "clubs", "hearts"]}"#,
        ).unwrap().schema;

        let expected = Schema::Enum {
            name: Name::new("Suit"),
            doc: None,
            symbols: vec![
                "diamonds".to_owned(),
                "spades".to_owned(),
                "clubs".to_owned(),
                "hearts".to_owned(),
            ],
        };

        assert_eq!(expected, schema);
    }

    #[test]
    fn test_fixed_schema() {
        let schema = Schema::parse_str(r#"{"type": "fixed", "name": "test", "size": 16}"#)
            .unwrap().schema;

        let expected = Schema::Fixed {
            name: Name::new("test"),
            size: 16usize,
        };

        assert_eq!(expected, schema);
    }

    #[test]
    fn test_nested_named_fixed_schema() {
        let schema = Schema::parse_str(
            r#"
            {
                "type": "record",
                "name": "test",
                "fields": [
                    {
                        "name": "a",
                        "type": {
                           "name": "fixed_test",
                           "namespace": "com.test",
                           "type": "fixed",
                           "size": 2
                         }
                    },
                    {
                        "name": "b",
                        "type": "com.test.fixed_test"
                    }
                ]
            }
        "#,
        ).unwrap().schema;

        let mut lookup = HashMap::new();
        lookup.insert("a".to_owned(), 0);
        lookup.insert("b".to_owned(), 1);

        let record_schema = RecordSchema::new(
            Name::new("test"),
            None,
            vec![
                RecordField {
                    name: "a".to_string(),
                    doc: None,
                    default: None,
                    schema: Schema::Fixed {
                        name: Name {
                            name: "fixed_test".to_string(),
                            namespace: Some("com.test".to_string()),
                            aliases: None,
                        },
                        size: 2usize,
                    },
                    order: RecordFieldOrder::Ascending,
                    position: 0,
                },
                RecordField {
                    name: "b".to_string(),
                    doc: None,
                    default: None,
                    schema: Schema::Reference(Name::new("com.test.fixed_test")),
                    order: RecordFieldOrder::Ascending,
                    position: 1,
                },
            ],
            lookup,
        );
        let expected = Schema::Record(record_schema);

        assert_eq!(expected, schema);
    }

    #[test]
    fn test_rercursive_record_schema() {
        let schema = Schema::parse_str(
            r#"
            {
                "type": "record",
                "name": "test",
                "fields": [
                    {
                        "name": "a",
                        "type": "test"
                    }
                ]
            }
        "#,
        ).unwrap().schema;

        let mut lookup = HashMap::new();
        lookup.insert("a".to_owned(), 0);

        let record_schema = RecordSchema::new(
            Name::new("test"),
            None,
            vec![
                RecordField {
                    name: "a".to_string(),
                    doc: None,
                    default: None,
                    schema: Schema::Reference(Name::new("test")),
                    order: RecordFieldOrder::Ascending,
                    position: 0,
                },
            ],
            lookup,
        );
        let expected = Schema::Record(record_schema);

        assert_eq!(expected, schema);
    }

    #[test]
    fn test_rercursive_record_schema_with_namespaces() {
        let schema = Schema::parse_str(
            r#"
            {
                "type": "record",
                "name": "test",
                "namespace": "com.test",
                "fields": [
                    {
                        "name": "a",
                        "type": "test"
                    }
                ]
            }
        "#,
        ).unwrap().schema;

        let mut lookup = HashMap::new();
        lookup.insert("a".to_owned(), 0);

        let record_schema = RecordSchema::new(
            Name {
                name: "test".to_string(),
                namespace: Some("com.test".to_string()),
                aliases: None,
            },
            None,
            vec![
                RecordField {
                    name: "a".to_string(),
                    doc: None,
                    default: None,
                    schema: Schema::Reference(Name::new("test")),
                    order: RecordFieldOrder::Ascending,
                    position: 0,
                },
            ],
            lookup,
        );
        let expected = Schema::Record(record_schema);

        assert_eq!(expected, schema);
    }

    #[test]
    fn test_no_documentation() {
        let schema =
            Schema::parse_str(r#"{"type": "enum", "name": "Coin", "symbols": ["heads", "tails"]}"#)
                .unwrap()
                .schema;

        let doc = match schema {
            Schema::Enum { doc, .. } => doc,
            _ => return assert!(false),
        };

        assert!(doc.is_none());
    }

    #[test]
    fn test_documentation() {
        let schema = Schema::parse_str(
            r#"{"type": "enum", "name": "Coin", "doc": "Some documentation", "symbols": ["heads", "tails"]}"#
        ).unwrap().schema;

        let doc = match schema {
            Schema::Enum { doc, .. } => doc,
            _ => None,
        };

        assert_eq!("Some documentation".to_owned(), doc.unwrap());
    }

    // Tests to ensure Schema is Send + Sync. These tests don't need to _do_ anything, if they can
    // compile, they pass.
    #[test]
    fn test_schema_is_send() {
        fn send<S: Send>(_s: S) {}

        let schema = Schema::Null;
        send(schema);
    }

    #[test]
    fn test_schema_is_sync() {
        fn sync<S: Sync>(_s: S) {}

        let schema = Schema::Null;
        sync(&schema);
        sync(schema);
    }

    #[test]
    fn test_schema_fingerprint() {
        use self::md5::Md5;
        use self::sha2::Sha256;

        let raw_schema = r#"
    {
        "type": "record",
        "name": "test",
        "fields": [
            {"name": "a", "type": "long", "default": 42},
            {"name": "b", "type": "string"}
        ]
    }
"#;

        let schema = Schema::parse_str(raw_schema).unwrap().schema;
        assert_eq!(
            "c4d97949770866dec733ae7afa3046757e901d0cfea32eb92a8faeadcc4de153",
            format!("{}", schema.fingerprint::<Sha256>())
        );

        assert_eq!(
            "7bce8188f28e66480a45ffbdc3615b7d",
            format!("{}", schema.fingerprint::<Md5>())
        );
    }

}
