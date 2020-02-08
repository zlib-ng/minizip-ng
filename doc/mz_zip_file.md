# MZ_ZIP_FILE

Minizip zip entry information structure. The _mz_zip_file_ structure can be populated and used for writing zip entry information. When retrieving information about a zip entry, it will be populated with the zip entry's information.

|Type|Name|Description|[PKWARE zip app note](zip/appnote.txt) section|
|-|-|-|-|
|uint16_t|version_madeby|Version made by field|4.4.2|
|uint16_t|version_needed|Version needed to extract|4.4.3|
|uint16_t|flag|General purpose bit flag|4.4.4|
|uint16_t|compression_method|Compression method|4.4.5|
|time_t|modified_date|Last modified unix timestamp|4.4.6, 4.5.5, 4.5.7|
|time_t|accessed_date|Last accessed unix timestamp|4.5.5, 4.5.7|
|time_t|creation_date|Creation date unix timestamp|4.5.5|
|uint32_t|crc|CRC-32 hash|4.4.7|
|int64_t|compressed_size|Compressed size|4.4.8|
|int64_t|uncompressed_size|Uncompressed size|4.4.9|
|uint16_t|filename_size|Filename length|4.4.10|
|uint16_t|extrafield_size|Extrafield length|4.4.11|
|uint16_t|comment_size|Comment size|4.4.12|
|uint32_t|disk_number|Starting disk number|4.4.13|
|int64_t|disk_offset|Starting disk offset|4.4.16|
|uint16_t|internal_fa|Internal file attributes|4.4.14|
|uint16_t|external_fa|External file attributes|4.4.15|
|const char *|filename|Filename UTF-8 null-terminated string|4.4.17|
|const uint8_t *|extrafield|Extrafield buffer array|4.4.28|
|const char *|comment|Comment UTF-8 null-terminated string|4.4.18|
|uint16_t|zip64|Zip64 extension mode|[MZ_ZIP64](mz_zip64)|
|uint16_t|aes_version|WinZip AES version|[WinZip AES App Note](zip/winzip_aes.md)|
|uint16_t|aes_encryption_mode|WinZip AES encryption mode|[WinZip AES App Note](zip/winzip_aes.md)|
