#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "jni.h"

// JVM 内部结构表示
typedef struct
{
    const char *name;
    const char *type;
    int64_t offset;
    int is_static;
} JVMStructField;

typedef struct
{
    const char *name;
    const char *superClass;
    int size;
    int is_oop;
    int is_integer;
    int is_unsigned;
    JVMStructField *fields;
    int field_count;
} JVMType;

typedef struct
{
    const char *name;
    void *address;
} JVMFlag;

static HMODULE g_jvm_module = NULL;

// 内存保护辅助函数
void write_byte(void *address, unsigned char value)
{
    MEMORY_BASIC_INFORMATION mbi;
    DWORD oldProtect;
    if (VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        if (VirtualProtect(mbi.BaseAddress, mbi.RegionSize, PAGE_READWRITE, &oldProtect))
        {
            *(unsigned char *)address = value;
            VirtualProtect(mbi.BaseAddress, mbi.RegionSize, oldProtect, &oldProtect);
        }
    }
}

#include "utils.c"

// 使用 JNI findNative 查找本地符号
void *find_native_symbol(const char *symbol_name)
{

    return (void *)(intptr_t)GetProcAddressPeb(g_jvm_module, symbol_name);
}

// 从内存地址读取字符串
char *read_string_from_address(uintptr_t addr)
{
    if (addr == 0)
        return NULL;

    char *current = (char *)addr;
    int len = 0;
    while (current[len] != '\0')
    {
        len++;
    }

    char *result = (char *)malloc(len + 1);
    if (!result)
        return NULL;

    memcpy(result, current, len);
    result[len] = '\0';
    return result;
}

// 获取 JVM 结构体
JVMStructField *get_structs(int *count)
{
    // 查找符号
    void *gHotSpotVMStructs = find_native_symbol("gHotSpotVMStructs");
    void *gHotSpotVMStructEntryArrayStride = find_native_symbol("gHotSpotVMStructEntryArrayStride");
    void *gHotSpotVMStructEntryTypeNameOffset = find_native_symbol("gHotSpotVMStructEntryTypeNameOffset");
    void *gHotSpotVMStructEntryFieldNameOffset = find_native_symbol("gHotSpotVMStructEntryFieldNameOffset");
    void *gHotSpotVMStructEntryTypeStringOffset = find_native_symbol("gHotSpotVMStructEntryTypeStringOffset");
    void *gHotSpotVMStructEntryIsStaticOffset = find_native_symbol("gHotSpotVMStructEntryIsStaticOffset");
    void *gHotSpotVMStructEntryOffsetOffset = find_native_symbol("gHotSpotVMStructEntryOffsetOffset");
    void *gHotSpotVMStructEntryAddressOffset = find_native_symbol("gHotSpotVMStructEntryAddressOffset");

    printf("Symbol lookup:\n");
    printf("gHotSpotVMStructs: %p\n", gHotSpotVMStructs);
    printf("gHotSpotVMStructEntryArrayStride: %p\n", gHotSpotVMStructEntryArrayStride);
    printf("gHotSpotVMStructEntryTypeNameOffset: %p\n", gHotSpotVMStructEntryTypeNameOffset);
    printf("gHotSpotVMStructEntryFieldNameOffset: %p\n", gHotSpotVMStructEntryFieldNameOffset);
    printf("gHotSpotVMStructEntryIsStaticOffset: %p\n", gHotSpotVMStructEntryIsStaticOffset);
    printf("gHotSpotVMStructEntryOffsetOffset: %p\n", gHotSpotVMStructEntryOffsetOffset);
    printf("gHotSpotVMStructEntryAddressOffset: %p\n", gHotSpotVMStructEntryAddressOffset);

    if (!gHotSpotVMStructs || !gHotSpotVMStructEntryArrayStride ||
        !gHotSpotVMStructEntryTypeNameOffset || !gHotSpotVMStructEntryFieldNameOffset ||
        !gHotSpotVMStructEntryIsStaticOffset || !gHotSpotVMStructEntryOffsetOffset ||
        !gHotSpotVMStructEntryAddressOffset)
    {
        printf("Required symbols not found\n");
        return NULL;
    }

    // 读取偏移量值
    int64_t stride = *(int64_t *)gHotSpotVMStructEntryArrayStride;
    int64_t typeNameOffset_val = *(int64_t *)gHotSpotVMStructEntryTypeNameOffset;
    int64_t fieldNameOffset_val = *(int64_t *)gHotSpotVMStructEntryFieldNameOffset;
    int64_t typeStringOffset_val = *(int64_t *)gHotSpotVMStructEntryTypeStringOffset;
    int64_t isStaticOffset_val = *(int64_t *)gHotSpotVMStructEntryIsStaticOffset;
    int64_t offsetOffset_val = *(int64_t *)gHotSpotVMStructEntryOffsetOffset;
    int64_t addressOffset_val = *(int64_t *)gHotSpotVMStructEntryAddressOffset;

    printf("Offsets:\n");
    printf("  Stride: %lld\n", stride);
    printf("  typeNameOffset: %lld\n", typeNameOffset_val);
    printf("  fieldNameOffset: %lld\n", fieldNameOffset_val);
    printf("  typeStringOffset: %lld\n", typeStringOffset_val);
    printf("  isStaticOffset: %lld\n", isStaticOffset_val);
    printf("  offsetOffset: %lld\n", offsetOffset_val);
    printf("  addressOffset: %lld\n", addressOffset_val);

    // 获取结构体数组起始地址
    uintptr_t structs_array = *(uintptr_t *)gHotSpotVMStructs;
    printf("Structs array at: %p\n", (void *)structs_array);

    if (structs_array == 0)
    {
        printf("Structs array is NULL\n");
        return NULL;
    }

    JVMStructField *structs = NULL;
    int capacity = 100;
    int size = 0;
    structs = (JVMStructField *)malloc(capacity * sizeof(JVMStructField));

    uintptr_t currentEntry = structs_array;
    int entryIndex = 0;

    while (1)
    {
        printf("\nProcessing entry %d at %p\n", entryIndex, (void *)currentEntry);

        // 读取类型名称地址
        uintptr_t typeNameAddr = *(uintptr_t *)(currentEntry + typeNameOffset_val);
        char *typeName = read_string_from_address(typeNameAddr);
        if (!typeName || strlen(typeName) == 0)
        {
            printf("  Empty type name, stopping\n");
            if (typeName)
                free(typeName);
            break;
        }
        printf("  typeName: %s\n", typeName);

        // 读取字段名称地址
        uintptr_t fieldNameAddr = *(uintptr_t *)(currentEntry + fieldNameOffset_val);
        char *fieldName = read_string_from_address(fieldNameAddr);
        if (!fieldName)
        {
            printf("  Empty field name, skipping\n");
            free(typeName);
            currentEntry += stride;
            entryIndex++;
            continue;
        }
        printf("  fieldName: %s\n", fieldName);

        // 读取类型字符串地址
        uintptr_t typeStringAddr = *(uintptr_t *)(currentEntry + typeStringOffset_val);
        char *typeString = read_string_from_address(typeStringAddr);
        if (typeString)
        {
            printf("  typeString: %s\n", typeString);
        }

        // 读取是否为静态字段
        int is_static = *(int *)(currentEntry + isStaticOffset_val);
        printf("  is_static: %d\n", is_static);

        // 读取偏移量或地址
        int64_t offset_value;
        if (is_static)
        {
            offset_value = *(int64_t *)(currentEntry + addressOffset_val);
            printf("  Static address: 0x%llx\n", offset_value);
        }
        else
        {
            offset_value = *(int64_t *)(currentEntry + offsetOffset_val);
            printf("  Instance offset: %lld\n", offset_value);
        }

        // 添加到结构体数组
        if (size >= capacity)
        {
            capacity *= 2;
            structs = (JVMStructField *)realloc(structs, capacity * sizeof(JVMStructField));
        }

        structs[size] = (JVMStructField){
            .name = strdup(fieldName),
            .type = strdup(typeName),
            .offset = offset_value,
            .is_static = is_static};
        size++;

        free(typeName);
        free(fieldName);
        if (typeString)
            free(typeString);

        // 移动到下一个条目
        currentEntry += stride;
        entryIndex++;
    }

    *count = size;
    printf("Found %d struct fields\n", size);
    return structs;
}

// 获取 JVM 类型
JVMType *get_types(JVMStructField *structs, int struct_count, int *type_count)
{
    // 查找符号
    void *gHotSpotVMTypes = find_native_symbol("gHotSpotVMTypes");
    void *gHotSpotVMTypeEntryArrayStride = find_native_symbol("gHotSpotVMTypeEntryArrayStride");
    void *gHotSpotVMTypeEntryTypeNameOffset = find_native_symbol("gHotSpotVMTypeEntryTypeNameOffset");
    void *gHotSpotVMTypeEntrySuperclassNameOffset = find_native_symbol("gHotSpotVMTypeEntrySuperclassNameOffset");
    void *gHotSpotVMTypeEntrySizeOffset = find_native_symbol("gHotSpotVMTypeEntrySizeOffset");
    void *gHotSpotVMTypeEntryIsOopTypeOffset = find_native_symbol("gHotSpotVMTypeEntryIsOopTypeOffset");
    void *gHotSpotVMTypeEntryIsIntegerTypeOffset = find_native_symbol("gHotSpotVMTypeEntryIsIntegerTypeOffset");
    void *gHotSpotVMTypeEntryIsUnsignedOffset = find_native_symbol("gHotSpotVMTypeEntryIsUnsignedOffset");

    printf("Type symbol lookup:\n");
    printf("gHotSpotVMTypes: %p\n", gHotSpotVMTypes);
    printf("gHotSpotVMTypeEntryArrayStride: %p\n", gHotSpotVMTypeEntryArrayStride);
    printf("gHotSpotVMTypeEntryTypeNameOffset: %p\n", gHotSpotVMTypeEntryTypeNameOffset);

    if (!gHotSpotVMTypes || !gHotSpotVMTypeEntryArrayStride ||
        !gHotSpotVMTypeEntryTypeNameOffset)
    {
        printf("Required type symbols not found\n");
        return NULL;
    }

    // 读取偏移量值
    int64_t stride = *(int64_t *)gHotSpotVMTypeEntryArrayStride;
    int64_t typeNameOffset = *(int64_t *)gHotSpotVMTypeEntryTypeNameOffset;
    int64_t superNameOffset = *(int64_t *)gHotSpotVMTypeEntrySuperclassNameOffset;
    int64_t sizeOffset = *(int64_t *)gHotSpotVMTypeEntrySizeOffset;
    int64_t isOopOffset = *(int64_t *)gHotSpotVMTypeEntryIsOopTypeOffset;
    int64_t isIntegerOffset = *(int64_t *)gHotSpotVMTypeEntryIsIntegerTypeOffset;
    int64_t isUnsignedOffset = *(int64_t *)gHotSpotVMTypeEntryIsUnsignedOffset;

    printf("Type stride: %lld\n", stride);
    printf("typeNameOffset: %lld\n", typeNameOffset);

    // 获取类型数组起始地址
    uintptr_t types_array = *(uintptr_t *)gHotSpotVMTypes;
    printf("Types array at: %p\n", (void *)types_array);

    if (types_array == 0)
    {
        printf("Types array is NULL\n");
        return NULL;
    }

    JVMType *types = NULL;
    int capacity = 50;
    int size = 0;
    types = (JVMType *)malloc(capacity * sizeof(JVMType));

    uintptr_t currentEntry = types_array;
    int entryIndex = 0;

    while (1)
    {
        printf("Processing type entry %d at %p\n", entryIndex, (void *)currentEntry);

        // 读取类型名称地址
        uintptr_t typeNameAddr = *(uintptr_t *)(currentEntry + typeNameOffset);
        printf("  typeNameAddr: %p\n", (void *)typeNameAddr);

        char *typeName = read_string_from_address(typeNameAddr);
        if (!typeName || strlen(typeName) == 0)
        {
            printf("  Empty type name, stopping\n");
            if (typeName)
                free(typeName);
            break;
        }
        printf("  typeName: %s\n", typeName);

        // 读取父类名称地址
        char *superName = NULL;
        if (superNameOffset != 0)
        {
            uintptr_t superNameAddr = *(uintptr_t *)(currentEntry + superNameOffset);
            printf("  superNameAddr: %p\n", (void *)superNameAddr);
            superName = read_string_from_address(superNameAddr);
            printf("  superName: %s\n", superName ? superName : "NULL");
        }

        // 读取类型属性
        int typeSize = 0;
        if (sizeOffset != 0)
        {
            typeSize = *(int *)(currentEntry + sizeOffset);
        }
        printf("  size: %d\n", typeSize);

        int isOop = 0;
        if (isOopOffset != 0)
        {
            isOop = *(int *)(currentEntry + isOopOffset);
        }

        int isInteger = 0;
        if (isIntegerOffset != 0)
        {
            isInteger = *(int *)(currentEntry + isIntegerOffset);
        }

        int isUnsigned = 0;
        if (isUnsignedOffset != 0)
        {
            isUnsigned = *(int *)(currentEntry + isUnsignedOffset);
        }

        // 收集此类型的字段
        JVMStructField *fields = NULL;
        int field_count = 0;
        for (int i = 0; i < struct_count; i++)
        {
            // 查找匹配的字段
            if (strcmp(structs[i].type, typeName) == 0)
            {
                field_count++;
            }
        }

        if (field_count > 0)
        {
            fields = (JVMStructField *)malloc(field_count * sizeof(JVMStructField));
            int idx = 0;
            for (int i = 0; i < struct_count; i++)
            {
                if (strcmp(structs[i].type, typeName) == 0)
                {
                    fields[idx] = structs[i];
                    printf("    Field: %s (%s)\n", fields[idx].name, fields[idx].type);
                    idx++;
                }
            }
        }

        // 添加到类型数组
        if (size >= capacity)
        {
            capacity *= 2;
            types = (JVMType *)realloc(types, capacity * sizeof(JVMType));
        }

        types[size] = (JVMType){
            .name = strdup(typeName),
            .superClass = superName ? strdup(superName) : NULL,
            .size = typeSize,
            .is_oop = isOop,
            .is_integer = isInteger,
            .is_unsigned = isUnsigned,
            .fields = fields,
            .field_count = field_count};
        size++;

        free(typeName);
        if (superName)
            free(superName);

        // 移动到下一个条目
        currentEntry += stride;
        entryIndex++;
    }

    *type_count = size;
    printf("Found %d JVM types\n", size);
    return types;
}

// 安全读取内存函数
int safe_read_int(void *address)
{
    if (!address)
        return 0;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        printf("VirtualQuery failed: %lu\n", GetLastError());
        return 0;
    }

    if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE)
    {
        printf("Memory at %p is not readable\n", address);
        return 0;
    }

    return *(int *)address;
}

uintptr_t safe_read_ptr(void *address)
{
    if (!address)
        return 0;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(address, &mbi, sizeof(mbi)))
    {
        printf("VirtualQuery failed: %lu\n", GetLastError());
        return 0;
    }

    if (mbi.Protect == PAGE_NOACCESS || mbi.Protect == PAGE_EXECUTE)
    {
        printf("Memory at %p is not readable\n", address);
        return 0;
    }

    return *(uintptr_t *)address;
}

// 获取 JVM 标志
JVMFlag *get_flags(JVMType *types, int type_count, int *flag_count)
{
    // 查找 Flag/JVMFlag 类型
    JVMType *flagType = NULL;
    printf("Looking for Flag type...\n");

    for (int i = 0; i < type_count; i++)
    {
        // printf("  Checking type: %s\n", types[i].name);

        // 检查类型名称
        if (strcmp(types[i].name, "Flag") == 0 ||
            strcmp(types[i].name, "JVMFlag") == 0)
        {
            flagType = &types[i];
            printf("Found Flag type: %s\n", flagType->name);
            break;
        }
    }

    if (!flagType)
    {
        printf("Flag type not found in %d types\n", type_count);
        return NULL;
    }

    // 查找 flags 字段
    JVMStructField *flagsField = NULL;
    for (int i = 0; i < flagType->field_count; i++)
    {
        if (strcmp(flagType->fields[i].name, "flags") == 0)
        {
            flagsField = &flagType->fields[i];
            printf("Found flags field: offset=%lld, static=%d\n",
                   flagsField->offset, flagsField->is_static);
            break;
        }
    }

    if (!flagsField)
    {
        printf("flags field not found in Flag type\n");
        return NULL;
    }

    // 查找 numFlags 字段
    JVMStructField *numFlagsField = NULL;
    for (int i = 0; i < flagType->field_count; i++)
    {
        if (strcmp(flagType->fields[i].name, "numFlags") == 0)
        {
            numFlagsField = &flagType->fields[i];
            printf("Found numFlags field at offset %lld\n", numFlagsField->offset);
            break;
        }
    }

    if (!numFlagsField)
    {
        printf("numFlags field not found in Flag type\n");
        return NULL;
    }

    // 查找名称和地址字段
    JVMStructField *nameField = NULL;
    JVMStructField *addrField = NULL;
    for (int i = 0; i < flagType->field_count; i++)
    {
        if (strcmp(flagType->fields[i].name, "_name") == 0)
        {
            nameField = &flagType->fields[i];
            printf("Found _name field at offset %lld\n", nameField->offset);
        }
        else if (strcmp(flagType->fields[i].name, "_addr") == 0)
        {
            addrField = &flagType->fields[i];
            printf("Found _addr field at offset %lld\n", addrField->offset);
        }
    }

    if (!nameField || !addrField)
    {
        printf("_name or _addr fields not found in Flag type\n");
        return NULL;
    }

    // 获取标志数组和数量
    uintptr_t flagsArray;
    if (flagsField->is_static)
    {
        uintptr_t flagsArrayPtr = (uintptr_t)flagsField->offset;
        flagsArray = *(uintptr_t *)flagsArrayPtr; // 关键解引用
    }
    else
    {
        printf("Non-static flags field not supported\n");
        return NULL;
    }

    int numFlags = 0;
    if (numFlagsField->is_static)
    {
        void *numFlagsAddr = (void *)(uintptr_t)numFlagsField->offset;
        numFlags = safe_read_int(numFlagsAddr);
    }

    if (numFlags <= 0 || numFlags > 10000)
    { // 添加合理性检查
        printf("Invalid numFlags: %d\n", numFlags);
        return NULL;
    }

    printf("Flags array at: %p\n", (void *)flagsArray);
    printf("Number of flags: %d\n", numFlags);

    // 收集标志
    JVMFlag *flags = (JVMFlag *)malloc(numFlags * sizeof(JVMFlag));
    if (!flags)
    {
        printf("Memory allocation failed for flags\n");
        return NULL;
    }

    int count = 0;

    for (int i = 0; i < numFlags; i++)
    {
        uintptr_t flagAddr = flagsArray + (i * flagType->size);

        // 读取名称指针
        uintptr_t namePtrAddr = flagAddr + nameField->offset;
        uintptr_t namePtr = safe_read_ptr((void *)namePtrAddr);
        char *name = namePtr ? read_string_from_address(namePtr) : NULL;

        // 读取值地址（直接解引用）
        uintptr_t valueAddrPtr = flagAddr + addrField->offset;
        void *valueAddr = *(void **)valueAddrPtr;

        if (name && valueAddr)
        {
            flags[count] = (JVMFlag){strdup(name), valueAddr};
            count++;
        }
    }

    *flag_count = count;
    return flags;
}

// 通过修改 JVM 标志禁用字节码验证
int disable_bytecode_verifier()
{
    printf("Attempting to disable JVM bytecode verifier...\n");
    printf("Trying to get JVM structs and types...\n");

    int struct_count = 0;
    int success = 0;
    JVMStructField *structs = get_structs(&struct_count);
    if (!structs || struct_count == 0)
    {
        printf("Failed to get JVM structs\n");
        return 0;
    }

    int type_count = 0;
    JVMType *types = get_types(structs, struct_count, &type_count);
    if (!types || type_count == 0)
    {
        printf("Failed to get JVM types\n");
        // 清理结构体资源
        for (int i = 0; i < struct_count; i++)
        {
            free((void *)structs[i].name);
            free((void *)structs[i].type);
        }
        free(structs);
        return 0;
    }

    int flag_count = 0;
    JVMFlag *flags = get_flags(types, type_count, &flag_count);
    if (!flags || flag_count == 0)
    {
        printf("Failed to get JVM flags\n");
    }
    else
    {
        for (int i = 0; i < flag_count; i++)
        {
            if (strcmp(flags[i].name, "BytecodeVerificationLocal") == 0 ||
                strcmp(flags[i].name, "BytecodeVerificationRemote") == 0)
            {

                printf("Found flag: %s at %p\n",
                       flags[i].name, flags[i].address);

                if (flags[i].address)
                {
                    write_byte(flags[i].address, 0);
                    printf("Disabled %s\n", flags[i].name);
                    success = 1;
                }
            }
        }

        // 释放标志资源
        for (int i = 0; i < flag_count; i++)
        {
            free((void *)flags[i].name);
        }
        free(flags);
    }

    // 清理类型资源
    for (int i = 0; i < type_count; i++)
    {
        free((void *)types[i].name);
        if (types[i].superClass)
            free((void *)types[i].superClass);
        if (types[i].fields)
        {
            // 注意：字段名称在结构体中已释放
            free(types[i].fields);
        }
    }
    free(types);

    // 清理结构体资源
    for (int i = 0; i < struct_count; i++)
    {
        free((void *)structs[i].name);
        free((void *)structs[i].type);
    }
    free(structs);

    if (success)
    {
        printf("Bytecode verifier disabled via flags\n");
        return 1;
    }

    printf("Failed to disable bytecode verifier\n");
    return 0;
}

JNIEXPORT jint JNICALL JNI_OnLoad(JavaVM *vm, void *reserved)
{
    g_jvm_module = GetModuleHandle("jvm.dll");
    if (!g_jvm_module)
    {
        printf("Failed to get jvm module\n");
    }

    if (disable_bytecode_verifier())
    {
        printf("Bytecode verifier disabled successfully!\n");
    }
    else
    {
        printf("Failed to disable bytecode verifier\n");
    }

    return JNI_VERSION_1_8;
}