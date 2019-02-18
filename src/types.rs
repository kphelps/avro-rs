//! Logic handling the intermediate representation of Avro values.
use std::collections::HashMap;
use std::hash::BuildHasher;

use failure::Error;
use serde_json::Value as JsonValue;

use crate::schema::{Name, RecordField, RecordSchemaRef, FullSchema, Schema, SchemaKind, SchemaTypes, UnionSchema, UnionRef};

/// Describes errors happened while performing schema resolution on Avro data.
#[derive(Fail, Debug)]
#[fail(display = "Decoding error: {}", _0)]
pub struct SchemaResolutionError(String);

impl SchemaResolutionError {
    pub fn new<S>(msg: S) -> SchemaResolutionError
    where
        S: Into<String>,
    {
        SchemaResolutionError(msg.into())
    }
}

/// Represents any valid Avro value
/// More information about Avro values can be found in the
/// [Avro Specification](https://avro.apache.org/docs/current/spec.html#schemas)
#[derive(Clone, Debug, PartialEq)]
pub enum Value {
    /// A `null` Avro value.
    Null,
    /// A `boolean` Avro value.
    Boolean(bool),
    /// A `int` Avro value.
    Int(i32),
    /// A `long` Avro value.
    Long(i64),
    /// A `float` Avro value.
    Float(f32),
    /// A `double` Avro value.
    Double(f64),
    /// A `bytes` Avro value.
    Bytes(Vec<u8>),
    /// A `string` Avro value.
    String(String),
    /// A `fixed` Avro value.
    /// The size of the fixed value is represented as a `usize`.
    Fixed(usize, Vec<u8>),
    /// An `enum` Avro value.
    ///
    /// An Enum is represented by a symbol and its position in the symbols list
    /// of its corresponding schema.
    /// This allows schema-less encoding, as well as schema resolution while
    /// reading values.
    Enum(i32, String),
    /// An `union` Avro value.
    Union(UnionRef, Box<Value>),
    /// An `array` Avro value.
    Array(Vec<Value>),
    /// A `map` Avro value.
    Map(HashMap<String, Value>),
    /// A `record` Avro value.
    ///
    /// A Record is represented by a vector of (`<record name>`, `value`).
    /// This allows schema-less encoding.
    ///
    /// See [Record](types.Record) for a more user-friendly support.
    Record(Vec<(String, Value)>),
}

/// Any structure implementing the [ToAvro](trait.ToAvro.html) trait will be usable
/// from a [Writer](../writer/struct.Writer.html).
pub trait ToAvro {
    /// Transforms this value into an Avro-compatible [Value](enum.Value.html).
    fn avro(self) -> Value;
    fn union_ref(&self) -> UnionRef;
}

macro_rules! to_avro(
    ($t:ty, $v:expr, $k:expr) => (
        impl ToAvro for $t {
            fn avro(self) -> Value {
                $v(self)
            }

            fn union_ref(&self) -> UnionRef {
                UnionRef::primitive($k)
            }
        }
    );
);

to_avro!(bool, Value::Boolean, SchemaKind::Boolean);
to_avro!(i32, Value::Int, SchemaKind::Int);
to_avro!(i64, Value::Long, SchemaKind::Long);
to_avro!(f32, Value::Float, SchemaKind::Float);
to_avro!(f64, Value::Double, SchemaKind::Double);
to_avro!(String, Value::String, SchemaKind::String);

impl ToAvro for () {
    fn avro(self) -> Value {
        Value::Null
    }

    fn union_ref(&self) -> UnionRef {
        UnionRef::primitive(SchemaKind::Null)
    }
}

impl ToAvro for usize {
    fn avro(self) -> Value {
        (self as i64).avro()
    }

    fn union_ref(&self) -> UnionRef {
        (*self as i64).union_ref()
    }
}

impl<'a> ToAvro for &'a str {
    fn avro(self) -> Value {
        Value::String(self.to_owned())
    }

    fn union_ref(&self) -> UnionRef {
        UnionRef::primitive(SchemaKind::String)
    }
}

impl<'a> ToAvro for &'a [u8] {
    fn avro(self) -> Value {
        Value::Bytes(self.to_owned())
    }

    fn union_ref(&self) -> UnionRef {
        UnionRef::primitive(SchemaKind::Bytes)
    }
}

impl<T> ToAvro for Option<T>
where
    T: ToAvro,
{
    fn avro(self) -> Value {
        let union_ref = self.union_ref();
        let v = match self {
            Some(v) => T::avro(v),
            None => Value::Null,
        };
        Value::Union(union_ref, Box::new(v))
    }

    fn union_ref(&self) -> UnionRef {
        match *self {
            Some(ref v) => v.union_ref(),
            None => UnionRef::primitive(SchemaKind::Null),
        }
    }
}

impl<T, S: BuildHasher> ToAvro for HashMap<String, T, S>
where
    T: ToAvro,
{
    fn avro(self) -> Value {
        Value::Map(
            self.into_iter()
                .map(|(key, value)| (key, value.avro()))
                .collect::<_>(),
        )
    }

    fn union_ref(&self) -> UnionRef {
        UnionRef::primitive(SchemaKind::Map)
    }
}

impl<'a, T, S: BuildHasher> ToAvro for HashMap<&'a str, T, S>
where
    T: ToAvro,
{
    fn avro(self) -> Value {
        Value::Map(
            self.into_iter()
                .map(|(key, value)| (key.to_owned(), value.avro()))
                .collect::<_>(),
        )
    }

    fn union_ref(&self) -> UnionRef {
        UnionRef::primitive(SchemaKind::Map)
    }
}

impl ToAvro for Value {
    fn avro(self) -> Value {
        self
    }

    fn union_ref(&self) -> UnionRef {
        UnionRef::primitive(SchemaKind::from(self))
    }
}

/*
impl<S: Serialize> ToAvro for S {
    fn avro(self) -> Value {
        use ser::Serializer;

        self.serialize(&mut Serializer::new()).unwrap()
    }
}
*/

/// Utility interface to build `Value::Record` objects.
#[derive(Debug, Clone)]
pub struct Record<'a> {
    /// List of fields contained in the record.
    /// Ordered according to the fields in the schema given to create this
    /// `Record` object. Any unset field defaults to `Value::Null`.
    pub fields: Vec<(String, Value)>,
    schema_lookup: &'a HashMap<String, usize>,
    name: Name,
}

impl<'a> Record<'a> {
    /// Create a `Record` given a `Schema`.
    ///
    /// If the `Schema` is not a `Schema::Record` variant, `None` will be returned.
    pub fn new(schema: &Schema) -> Option<Record> {
        match *schema {
            Schema::Record(ref record) => {
                let mut fields = Vec::with_capacity(record.fields.len());
                for schema_field in record.fields.iter() {
                    fields.push((schema_field.name.clone(), Value::Null));
                }

                Some(Record {
                    fields,
                    schema_lookup: &record.lookup,
                    name: record.name.clone(),
                })
            },
            _ => None,
        }
    }

    pub fn from_ref(schema: &'a RecordSchemaRef<'a>) -> Record<'a> {
        let schema_fields = schema.fields();
        let mut fields = Vec::with_capacity(schema_fields.len());
        schema_fields.iter().for_each(|field| fields.push((field.name().to_string(), Value::Null)));
        Record {
            fields,
            schema_lookup: &schema.lookup(),
            name: schema.name().clone(),
        }
    }

    /// Put a compatible value (implementing the `ToAvro` trait) in the
    /// `Record` for a given `field` name.
    ///
    /// **NOTE** Only ensure that the field name is present in the `Schema` given when creating
    /// this `Record`. Does not perform any schema validation.
    pub fn put<V>(&mut self, field: &str, value: V)
    where
        V: ToAvro,
    {
        if let Some(&position) = self.schema_lookup.get(field) {
            self.fields[position].1 = value.avro()
        }
    }
}

impl<'a> ToAvro for Record<'a> {
    fn avro(self) -> Value {
        Value::Record(self.fields)
    }

    fn union_ref(&self) -> UnionRef {
        UnionRef::named(&self.name)
    }
}

impl ToAvro for JsonValue {
    fn avro(self) -> Value {
        match self {
            JsonValue::Null => Value::Null,
            JsonValue::Bool(b) => Value::Boolean(b),
            JsonValue::Number(ref n) if n.is_i64() => Value::Long(n.as_i64().unwrap()),
            JsonValue::Number(ref n) if n.is_f64() => Value::Double(n.as_f64().unwrap()),
            JsonValue::Number(n) => Value::Long(n.as_u64().unwrap() as i64), // TODO: Not so great
            JsonValue::String(s) => Value::String(s),
            JsonValue::Array(items) => {
                Value::Array(items.into_iter().map(|item| item.avro()).collect::<_>())
            },
            JsonValue::Object(items) => Value::Map(
                items
                    .into_iter()
                    .map(|(key, value)| (key, value.avro()))
                    .collect::<_>(),
            ),
        }
    }

    fn union_ref(&self) -> UnionRef {
        let kind = match self {
            JsonValue::Null => SchemaKind::Null,
            JsonValue::Bool(_) => SchemaKind::Boolean,
            JsonValue::Number(ref n) if n.is_i64() => SchemaKind::Long,
            JsonValue::Number(ref n) if n.is_f64() => SchemaKind::Double,
            JsonValue::Number(_) => SchemaKind::Long,
            JsonValue::String(_) => SchemaKind::String,
            JsonValue::Array(_) => SchemaKind::Array,
            JsonValue::Object(_) => SchemaKind::Map,
        };
        UnionRef::primitive(kind)
    }
}

impl Value {
    /// Validate the value against the given [Schema](../schema/enum.Schema.html).
    ///
    /// See the [Avro specification](https://avro.apache.org/docs/current/spec.html)
    /// for the full set of rules of schema validation.
    pub fn validate(&self, schema: &FullSchema) -> bool {
        self.validate_with_context(&schema.schema, &schema.types)
    }

    fn validate_with_context(&self, schema: &Schema, types: &SchemaTypes) -> bool {
        if let Schema::Reference(ref name) = *schema {
            let resolved = types.get(&name.fullname(None)).unwrap();
            return self.validate_with_context(resolved, types);
        }
        match (self, schema) {
            (&Value::Null, &Schema::Null) => true,
            (&Value::Boolean(_), &Schema::Boolean) => true,
            (&Value::Int(_), &Schema::Int) => true,
            (&Value::Long(_), &Schema::Long) => true,
            (&Value::Float(_), &Schema::Float) => true,
            (&Value::Double(_), &Schema::Double) => true,
            (&Value::Bytes(_), &Schema::Bytes) => true,
            (&Value::String(_), &Schema::String) => true,
            (&Value::Fixed(n, _), &Schema::Fixed { size, .. }) => n == size,
            (&Value::String(ref s), &Schema::Fixed { size, .. }) => s.len() == size,
            (&Value::String(ref s), &Schema::Enum { ref symbols, .. }) => symbols.contains(s),
            (&Value::Enum(i, ref s), &Schema::Enum { ref symbols, .. }) => symbols
                .get(i as usize)
                .map(|ref symbol| symbol == &s)
                .unwrap_or(false),
            // (&Value::Union(None), &Schema::Union(_)) => true,
            (&Value::Union(ref union_ref, ref value), &Schema::Union(ref inner)) => {
                inner.find_ref(union_ref)
                    .map(|(_, value_schema)| value.validate_with_context(value_schema, types))
                    .unwrap_or(false)
            },
            (&Value::Array(ref items), &Schema::Array(ref inner)) => {
                items.iter().all(|item| item.validate_with_context(inner, types))
            },
            (&Value::Map(ref items), &Schema::Map(ref inner)) => {
                items.iter().all(|(_, value)| value.validate_with_context(inner, types))
            },
            (&Value::Record(ref record_fields), &Schema::Record(ref record_schema)) => {
                record_schema.fields.len() == record_fields.len()
                    && record_schema.fields.iter().zip(record_fields.iter()).all(|(field, &(ref name, ref value))| {
                        field.name == *name && value.validate_with_context(&field.schema, types)
                    })
            },
            _ => false,
        }
    }

    /// Attempt to perform schema resolution on the value, with the given
    /// [Schema](../schema/enum.Schema.html).
    ///
    /// See [Schema Resolution](https://avro.apache.org/docs/current/spec.html#Schema+Resolution)
    /// in the Avro specification for the full set of rules of schema
    /// resolution.
    pub fn resolve(self, schema: &FullSchema) -> Result<Self, Error> {
        self.resolve_with_context(&schema.schema, &schema.types)
    }

    pub fn resolve_with_context(mut self, schema: &Schema, types: &SchemaTypes)
        -> Result<Self, Error>
    {
        // Check if this schema is a union, and if the reader schema is not.
        if SchemaKind::from(&self) == SchemaKind::Union
            && SchemaKind::from(schema) != SchemaKind::Union
        {
            // Pull out the Union, and attempt to resolve against it.
            let v = match self {
                Value::Union(_, b) => *b,
                _ => unreachable!(),
            };
            self = v;
        }
        match *schema {
            Schema::Null => self.resolve_null(),
            Schema::Boolean => self.resolve_boolean(),
            Schema::Int => self.resolve_int(),
            Schema::Long => self.resolve_long(),
            Schema::Float => self.resolve_float(),
            Schema::Double => self.resolve_double(),
            Schema::Bytes => self.resolve_bytes(),
            Schema::String => self.resolve_string(),
            Schema::Fixed { size, .. } => self.resolve_fixed(size),
            Schema::Union(ref inner) => self.resolve_union(inner, types),
            Schema::Enum { ref symbols, .. } => self.resolve_enum(symbols),
            Schema::Array(ref inner) => self.resolve_array(inner, types),
            Schema::Map(ref inner) => self.resolve_map(inner, types),
            Schema::Record(ref record) => self.resolve_record(&record.fields, types),
            Schema::Reference(ref name) => self.resolve_reference(name, types),
        }
    }

    fn resolve_null(self) -> Result<Self, Error> {
        match self {
            Value::Null => Ok(Value::Null),
            other => {
                Err(SchemaResolutionError::new(format!("Null expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_boolean(self) -> Result<Self, Error> {
        match self {
            Value::Boolean(b) => Ok(Value::Boolean(b)),
            other => {
                Err(SchemaResolutionError::new(format!("Boolean expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_int(self) -> Result<Self, Error> {
        match self {
            Value::Int(n) => Ok(Value::Int(n)),
            Value::Long(n) => Ok(Value::Int(n as i32)),
            other => {
                Err(SchemaResolutionError::new(format!("Int expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_long(self) -> Result<Self, Error> {
        match self {
            Value::Int(n) => Ok(Value::Long(i64::from(n))),
            Value::Long(n) => Ok(Value::Long(n)),
            other => {
                Err(SchemaResolutionError::new(format!("Long expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_float(self) -> Result<Self, Error> {
        match self {
            Value::Int(n) => Ok(Value::Float(n as f32)),
            Value::Long(n) => Ok(Value::Float(n as f32)),
            Value::Float(x) => Ok(Value::Float(x)),
            Value::Double(x) => Ok(Value::Float(x as f32)),
            other => {
                Err(SchemaResolutionError::new(format!("Float expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_double(self) -> Result<Self, Error> {
        match self {
            Value::Int(n) => Ok(Value::Double(f64::from(n))),
            Value::Long(n) => Ok(Value::Double(n as f64)),
            Value::Float(x) => Ok(Value::Double(f64::from(x))),
            Value::Double(x) => Ok(Value::Double(x)),
            other => {
                Err(SchemaResolutionError::new(format!("Double expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_bytes(self) -> Result<Self, Error> {
        match self {
            Value::Bytes(bytes) => Ok(Value::Bytes(bytes)),
            Value::String(s) => Ok(Value::Bytes(s.into_bytes())),
            other => {
                Err(SchemaResolutionError::new(format!("Bytes expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_string(self) -> Result<Self, Error> {
        match self {
            Value::String(s) => Ok(Value::String(s)),
            Value::Bytes(bytes) => Ok(Value::String(String::from_utf8(bytes)?)),
            other => {
                Err(SchemaResolutionError::new(format!("String expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_fixed(self, size: usize) -> Result<Self, Error> {
        match self {
            Value::Fixed(n, bytes) => if n == size {
                Ok(Value::Fixed(n, bytes))
            } else {
                Err(SchemaResolutionError::new(format!(
                    "Fixed size mismatch, {} expected, got {}",
                    size, n
                )).into())
            },
            other => {
                Err(SchemaResolutionError::new(format!("String expected, got {:?}", other)).into())
            },
        }
    }

    fn resolve_enum(self, symbols: &[String]) -> Result<Self, Error> {
        let validate_symbol = |symbol: String, symbols: &[String]| {
            if let Some(index) = symbols.iter().position(|ref item| item == &&symbol) {
                Ok(Value::Enum(index as i32, symbol))
            } else {
                Err(SchemaResolutionError::new(format!(
                    "Enum default {} is not among allowed symbols {:?}",
                    symbol, symbols,
                )).into())
            }
        };

        match self {
            Value::Enum(i, s) => if i > 0 && i < symbols.len() as i32 {
                validate_symbol(s, symbols)
            } else {
                Err(SchemaResolutionError::new(format!(
                    "Enum value {} is out of bound {}",
                    i,
                    symbols.len() as i32
                )).into())
            },
            Value::String(s) => validate_symbol(s, symbols),
            other => Err(SchemaResolutionError::new(format!(
                "Enum({:?}) expected, got {:?}",
                symbols, other
            )).into()),
        }
    }

    fn resolve_union(self, schema: &UnionSchema, types: &SchemaTypes) -> Result<Self, Error> {
        let option: Option<(usize, &Schema)> = match self {
            // Both are unions case.
            Value::Union(ref union_ref, _) => schema.find_ref(union_ref),
            // Reader is a union, but writer is not.
            ref v => schema.find_schema(&v),
        };
        // Find the first match in the reader schema.
        let (_, inner) = option
            .ok_or_else(|| SchemaResolutionError::new("Could not find matching type in union"))?;
        let v = match self {
            Value::Union(_, v) => *v,
            v => v,
        };
        v.resolve_with_context(inner, types)
    }

    fn resolve_array(self, schema: &Schema, types: &SchemaTypes) -> Result<Self, Error> {
        match self {
            Value::Array(items) => Ok(Value::Array(
                items
                    .into_iter()
                    .map(|item| item.resolve_with_context(schema, types))
                    .collect::<Result<Vec<_>, _>>()?,
            )),
            other => Err(SchemaResolutionError::new(format!(
                "Array({:?}) expected, got {:?}",
                schema, other
            )).into()),
        }
    }

    fn resolve_map(self, schema: &Schema, types: &SchemaTypes) -> Result<Self, Error> {
        match self {
            Value::Map(items) => Ok(Value::Map(
                items
                    .into_iter()
                    .map(|(key, value)| value.resolve_with_context(schema, types).map(|value| (key, value)))
                    .collect::<Result<HashMap<_, _>, _>>()?,
            )),
            other => Err(SchemaResolutionError::new(format!(
                "Map({:?}) expected, got {:?}",
                schema, other
            )).into()),
        }
    }

    fn resolve_record(self, fields: &[RecordField], types: &SchemaTypes) -> Result<Self, Error> {
        let mut items = match self {
            Value::Map(items) => Ok(items),
            Value::Record(fields) => Ok(fields.into_iter().collect::<HashMap<_, _>>()),
            other => Err(Error::from(SchemaResolutionError::new(format!(
                "Record({:?}) expected, got {:?}",
                fields, other
            )))),
        }?;

        let new_fields = fields
            .iter()
            .map(|field| {
                let value = match items.remove(&field.name) {
                    Some(value) => value,
                    None => match field.default {
                        Some(ref value) => match field.schema {
                            Schema::Enum { ref symbols, .. } => {
                                value.clone().avro().resolve_enum(symbols)?
                            },
                            _ => value.clone().avro(),
                        },
                        _ => {
                            return Err(SchemaResolutionError::new(format!(
                                "missing field {} in record",
                                field.name
                            )).into())
                        },
                    },
                };
                value
                    .resolve_with_context(&field.schema, types)
                    .map(|value| (field.name.clone(), value))
            }).collect::<Result<Vec<_>, _>>()?;

        Ok(Value::Record(new_fields))
    }

    fn resolve_reference(self, name: &Name, types: &SchemaTypes) -> Result<Self, Error> {
        let schema = types.get(&name.fullname(None))
            .ok_or_else(|| SchemaResolutionError::new(format!(
                "missing reference {} in schema",
                name.name
            )))?;
        self.resolve_with_context(schema, types)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::schema::{Name, RecordField, RecordFieldOrder, UnionRef, UnionSchema};

    #[test]
    fn validate() {
        let value_schema_valid = vec![
            (Value::Int(42), Schema::Int, true),
            (Value::Int(42), Schema::Boolean, false),
            (
                Value::Union(UnionRef::primitive(SchemaKind::Null), Box::new(Value::Null)),
                Schema::Union(UnionSchema::new(vec![Schema::Null, Schema::Int]).unwrap()),
                true,
            ),
            (
                Value::Union(UnionRef::primitive(SchemaKind::Int), Box::new(Value::Int(42))),
                Schema::Union(UnionSchema::new(vec![Schema::Null, Schema::Int]).unwrap()),
                true,
            ),
            (
                Value::Union(UnionRef::primitive(SchemaKind::Null), Box::new(Value::Null)),
                Schema::Union(UnionSchema::new(vec![Schema::Double, Schema::Int]).unwrap()),
                false,
            ),
            (
                Value::Union(UnionRef::primitive(SchemaKind::Int), Box::new(Value::Int(42))),
                Schema::Union(
                    UnionSchema::new(vec![
                        Schema::Null,
                        Schema::Double,
                        Schema::String,
                        Schema::Int,
                    ]).unwrap(),
                ),
                true,
            ),
            (
                Value::Array(vec![Value::Long(42i64)]),
                Schema::Array(Box::new(Schema::Long)),
                true,
            ),
            (
                Value::Array(vec![Value::Boolean(true)]),
                Schema::Array(Box::new(Schema::Long)),
                false,
            ),
            (Value::Record(vec![]), Schema::Null, false),
        ];

        for (value, schema, valid) in value_schema_valid.into_iter() {
            assert_eq!(valid, value.validate(&schema.as_full_schema()));
        }
    }

    #[test]
    fn validate_fixed() {
        let schema = Schema::Fixed {
            size: 4,
            name: Name::new("some_fixed"),
        }.as_full_schema();

        assert!(Value::Fixed(4, vec![0, 0, 0, 0]).validate(&schema));
        assert!(!Value::Fixed(5, vec![0, 0, 0, 0, 0]).validate(&schema));
    }

    #[test]
    fn validate_enum() {
        let schema = Schema::Enum {
            name: Name::new("some_enum"),
            doc: None,
            symbols: vec![
                "spades".to_string(),
                "hearts".to_string(),
                "diamonds".to_string(),
                "clubs".to_string(),
            ],
        }.as_full_schema();

        assert!(Value::Enum(0, "spades".to_string()).validate(&schema));
        assert!(Value::String("spades".to_string()).validate(&schema));

        assert!(!Value::Enum(1, "spades".to_string()).validate(&schema));
        assert!(!Value::String("lorem".to_string()).validate(&schema));

        let other_schema = Schema::Enum {
            name: Name::new("some_other_enum"),
            doc: None,
            symbols: vec![
                "hearts".to_string(),
                "diamonds".to_string(),
                "clubs".to_string(),
                "spades".to_string(),
            ],
        }.as_full_schema();

        assert!(!Value::Enum(0, "spades".to_string()).validate(&other_schema));
    }

    #[test]
    fn validate_record() {
        // {
        //    "type": "record",
        //    "fields": [
        //      {"type": "long", "name": "a"},
        //      {"type": "string", "name": "b"}
        //    ]
        // }
        let schema = Schema::Record {
            name: Name::new("some_record"),
            doc: None,
            fields: vec![
                RecordField {
                    name: "a".to_string(),
                    doc: None,
                    default: None,
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
            lookup: HashMap::new(),
        }.as_full_schema();

        assert!(
            Value::Record(vec![
                ("a".to_string(), Value::Long(42i64)),
                ("b".to_string(), Value::String("foo".to_string())),
            ]).validate(&schema)
        );

        assert!(
            !Value::Record(vec![
                ("b".to_string(), Value::String("foo".to_string())),
                ("a".to_string(), Value::Long(42i64)),
            ]).validate(&schema)
        );

        assert!(
            !Value::Record(vec![
                ("a".to_string(), Value::Boolean(false)),
                ("b".to_string(), Value::String("foo".to_string())),
            ]).validate(&schema)
        );

        assert!(
            !Value::Record(vec![
                ("a".to_string(), Value::Long(42i64)),
                ("c".to_string(), Value::String("foo".to_string())),
            ]).validate(&schema)
        );

        assert!(
            !Value::Record(vec![
                ("a".to_string(), Value::Long(42i64)),
                ("b".to_string(), Value::String("foo".to_string())),
                ("c".to_string(), Value::Null),
            ]).validate(&schema)
        );
    }

    #[test]
    fn validate_union_with_records() {
        // [
        //   "null",
        //   {
        //     "type": "record",
        //     "name": "some_record",
        //     "fields": [
        //       {"type": "long", "name": "a"}
        //     ]
        //   },
        //   {
        //     "type": "record",
        //     "name": "other_record",
        //     "fields": [
        //       {"type": "string", "name": "b"}
        //     ]
        //   }
        // ]
        let some_record = Schema::Record {
            name: Name::new("some_record"),
            doc: None,
            fields: vec![
                RecordField {
                    name: "a".to_string(),
                    doc: None,
                    default: None,
                    schema: Schema::Long,
                    order: RecordFieldOrder::Ascending,
                    position: 0,
                },
            ],
            lookup: HashMap::new(),
        };
        let other_record = Schema::Record {
            name: Name::new("other_record"),
            doc: None,
            fields: vec![
                RecordField {
                    name: "b".to_string(),
                    doc: None,
                    default: None,
                    schema: Schema::String,
                    order: RecordFieldOrder::Ascending,
                    position: 1,
                },
            ],
            lookup: HashMap::new(),
        };
        let union_schema = UnionSchema::new(vec![
            Schema::Null,
            some_record,
            other_record,
        ]).unwrap();
        let schema = Schema::Union(union_schema).as_full_schema();

        let null_value = Box::new(Value::Null);
        let null_ref = UnionRef::primitive(SchemaKind::Null);
        let some_value = Box::new(Value::Record(vec![("a".to_string(), Value::Long(42i64))]));
        let some_ref = UnionRef::from_fullname("some_record".to_string());
        let other_value = Box::new(Value::Record(vec![("b".to_string(), Value::String("foo".to_string()))]));
        let other_ref = UnionRef::from_fullname("other_record".to_string());
        let missing_ref = UnionRef::from_fullname("missing".to_string());

        let validate = |union_ref: &UnionRef, value: &Box<Value>| -> bool {
            Value::Union(union_ref.clone(), value.clone()).validate(&schema)
        };

        assert!(validate(&null_ref, &null_value));
        assert!(validate(&some_ref, &some_value));
        assert!(validate(&other_ref, &other_value));
        assert!(!validate(&other_ref, &some_value));
        assert!(!validate(&other_ref, &null_value));
        assert!(!validate(&missing_ref, &null_value));
        assert!(!validate(&missing_ref, &some_value));
        assert!(!validate(&missing_ref, &other_value));
        assert!(!validate(&null_ref, &some_value));
    }
}
