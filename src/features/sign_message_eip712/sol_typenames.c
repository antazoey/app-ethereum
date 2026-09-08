#include "os_print.h"
#include "sol_typenames.h"
#include "typed_data.h"

/**
 * Get typename from a given field
 *
 * @param[in] field_ptr pointer to a struct field
 * @return typename or \ref NULL in case it wasn't found
 */
const char *get_struct_field_sol_typename(const s_struct_712_field *field_ptr) {
    if (field_ptr != NULL) {
        switch (field_ptr->type) {
            case TYPE_SOL_INT:
                return "int";
            case TYPE_SOL_UINT:
                return "uint";
            case TYPE_SOL_ADDRESS:
                return "address";
            case TYPE_SOL_BOOL:
                return "bool";
            case TYPE_SOL_STRING:
                return "string";
            case TYPE_SOL_BYTES_FIX:
            case TYPE_SOL_BYTES_DYN:
                return "bytes";
            default:
                PRINTF("Error: Unknown field type (%u)\n", field_ptr->type);
        }
    }
    return NULL;
}
