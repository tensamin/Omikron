pub mod file_util;
pub mod logger;

use mtp::codec::{DataType, DataTypeId, TypeMap};

/*
 * Omikron serializes fields using the latest TypeMap, whose built-in fields
 * are required by the protocol. Keep the invariant in one place while using
 * the non-deprecated conversion API.
 */
pub fn data_type_id(data_type: DataType, type_map: &TypeMap) -> DataTypeId {
    let Some(id) = data_type.try_to_id(type_map) else {
        panic!("required data type is missing from the TypeMap: {data_type:?}");
    };
    id
}
