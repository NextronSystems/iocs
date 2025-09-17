# Sindoor Dropper: New Phishing Campaign

The following IOCs are based on the analysis and research described in the following blog post

- [Sindoor Dropper: New Phishing Campaign](https://www.nextron-systems.com/2025/08/29/sindoor-dropper-new-phishing-campaign/)

## IOCs
| Type | Indicator | Family|
| ---- | ---- |  ---- |
| SHA-256 | 9943bdf1b2a37434054b14a1a56a8e67aaa6a8b733ca785017d3ed8c1173ac59 | Initial phishing payload|
| SHA-256 | ba5b485552ab775ce3116d9d5fa17f88452c1ae60118902e7f669fd6390eae97 | Decoy PDF Document |
| SHA-256 | 6879a2b730e391964afe4dbbc29667844ba0c29239be5503b7c86e59e7052443 | AES decryptor |
| SHA-256 | 9a1adb50bb08f5a28160802c8f315749b15c9009f25aa6718c7752471db3bb4b | AES decryptor |
| SHA-256 | 231957a5b5b834f88925a1922dba8b4238cf13b0e92c17851a83f40931f264c1 | AES decryptor |
| SHA-256 | 0f4ef1da435d5d64ccc21b4c2a6967b240c2928b297086878b3dcb3e9c87aa23 | Downloader |
| SHA-256 | 38b6b93a536cbab5c289fe542656d8817d7c1217ad75c7f367b15c65d96a21d4 | Downloader |
| SHA-256 | 6b1420193a0ff96e3a19e887683535ab6654b2773a1899c2ab113739730924a1 | AES-CTR encrypted Stage2 |
| SHA-256 | a6aa76cf3f25c768cc6ddcf32a86e5fcf4d8dd95298240c232942ce5e08709ec | AES-CTR encrypted Stage3 |
| SHA-256 | b46889ed27b69b94fb741b4d03be7c91986ac08269f9d7c37d1c13ea711f6389 | Encrypted Mesh Agent |
| SHA-256 | 05b468fc24c93885cad40ff9ecb50594faa6c2c590e75c88a5e5f54a8b696ac8 | Mesh Agent |

## Additional Resources

### Yara

- [SUSP_LNX_Sindoor_ELF_Obfuscation_Aug25, SUSP_LNX_Sindoor_DesktopFile_Aug25, MAL_Sindoor_Decryptor_Aug25, MAL_Sindoor_Downloader_Aug25](https://github.com/Neo23x0/signature-base/blob/master/yara/apt_apt36_operation_sindoor.yar)

### Scripts

- [Idapython String Decryptor](./scripts/decode_meshagent_modules.py)
