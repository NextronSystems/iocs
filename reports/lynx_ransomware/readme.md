# In-Depth Analysis of Lynx Ransomware

The following IOCs are based on the analysis and research described in the following blog post:

- [In-Depth Analysis of Lynx Ransomware](https://www.nextron-systems.com/2024/10/11/in-depth-analysis-of-lynx-ransomware/)

## IOCs
| Type | Indicator | Family|
| ---- | ---- |  ---- |
| SHA-256 | eaa0e773eb593b0046452f420b6db8a47178c09e6db0fa68f6a2d42c3f48e3bc | LYNX Ransomware |
| SHA-256 | 571f5de9dd0d509ed7e5242b9b7473c2b2cbb36ba64d38b32122a0a337d6cf8b | LYNX Ransomware |
| SHA-256 | b378b7ef0f906358eec595777a50f9bb5cc7bb6635e0f031d65b818a26bdc4ee | LYNX Ransomware |
| SHA-256 | ecbfea3e7869166dd418f15387bc33ce46f2c72168f571071916b5054d7f6e49 | LYNX Ransomware |
| SHA-256 | 85699c7180ad77f2ede0b15862bb7b51ad9df0478ed394866ac7fa9362bf5683 | LYNX Ransomware |
| SHA-256 | 64b249eb3ab5993e7bcf5c0130e5f31cbd79dabdcad97268042780726e68533f | INC Ransomware |
| SHA-256 | 508a644d552f237615d1504aa1628566fe0e752a5bc0c882fa72b3155c322cef | INC Ransomware |
| SHA-256 | 7f104a3dfda3a7fbdd9b910d00b0169328c5d2facc10dc17b4378612ffa82d51 | INC Ransomware |
| SHA-256 | 1754c9973bac8260412e5ec34bf5156f5bb157aa797f95ff4fc905439b74357a | INC Ransomware |
| SHA-256 | d147b202e98ce73802d7501366a036ea8993c4c06cdfc6921899efdd22d159c6 | INC Ransomware |
| SHA-256 | 05e4f234a0f177949f375a56b1a875c9ca3d2bee97a2cb73fc2708914416c5a9 | INC Ransomware |
| SHA-256 | fef674fce37d5de43a4d36e86b2c0851d738f110a0d48bae4b2dab4c6a2c373e | INC Ransomware |
| SHA-256 | 36e3c83e50a19ad1048dab7814f3922631990578aab0790401bc67dbcc90a72e | INC Ransomware |
| SHA-256 | 869d6ae8c0568e40086fd817766a503bfe130c805748e7880704985890aca947 | INC Ransomware |
| SHA-256 | ee1d8ac9fef147f0751000c38ca5d72feceeaae803049a2cd49dcce15223b720 | INC Ransomware |
| SHA-256 | f96ecd567d9a05a6adb33f07880eebf1d6a8709512302e363377065ca8f98f56 | INC Ransomware |
| SHA-256 | 3156ee399296d55e56788b487701eb07fd5c49db04f80f5ab3dc5c4e3c071be0 | INC Ransomware |
| SHA-256 | fcefe50ed02c8d315272a94f860451bfd3d86fa6ffac215e69dfa26a7a5deced | INC Ransomware |
| SHA-256 | 11cfd8e84704194ff9c56780858e9bbb9e82ff1b958149d74c43969d06ea10bd | INC Ransomware |
| SHA-256 | 02472036db9ec498ae565b344f099263f3218ecb785282150e8565d5cac92461 | INC Ransomware |
| SHA-256 | e17c601551dfded76ab99a233957c5c4acf0229b46cd7fc2175ead7fe1e3d261 | INC Ransomware |
| SHA-256 | 9ac550187c7c27a52c80e1c61def1d3d5e6dbae0e4eaeacf1a493908ffd3ec7d | INC Ransomware |
| SHA-256 | ca9d2440850b730ba03b3a4f410760961d15eb87e55ec502908d2546cd6f598c | INC Ransomware |
| SHA-256 | 1a7c754ae1933338c740c807ec3dcf5e18e438356990761fdc2e75a2685ebf4a | INC Ransomware |
| SHA-256 | a5925db043e3142e31f21bc18549eb7df289d7c938d56dffe3f5905af11ab97a | INC Ransomware |
| SHA-256 | 7ccea71dcec6042d83692ea9e1348f249b970af2d73c83af3f9d67c4434b2dd0 | INC Ransomware |
| SHA-256 | 5a8883ad96a944593103f2f7f3a692ea3cde1ede71cf3de6750eb7a044a61486 | INC Ransomware |
| SHA-256 | 463075274e328bd47d8092f4901e67f7fff6c5d972b5ffcf821d3c988797e8e3 | INC Ransomware |
## Additional Resources

### Yara

- [MAL_RANSOM_INC_Aug24](https://github.com/Neo23x0/signature-base/blob/master/yara/mal_inc_ransomware.yar)

### Sigma

- [Potentially Suspicious Desktop Background Change Via Registry](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/registry/registry_set/registry_set_desktop_background_change.yml)

### IDA DB

- [LYNX IDA Database](./idadb/lynx.idb)
