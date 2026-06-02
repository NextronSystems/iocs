# Technical Analysis of UNC1549s infection chain

The following IOCs are based on the analysis and research described in the following blog post:

https://www.nextron-systems.com/2026/06/01/detecting-nimbus-manticore-and-their-sideloading-infection-chains/


## IOCs

| Hash                                                             | Description / Filename          |
| ---------------------------------------------------------------- | ------------------------------- |
| 06d12a4c4e3cc725dba37445cebeba41803718ccdb63d9d637355a241f651668 | Fake Airbus Job Description PDF |
| 9b63b744dc1f3a24f057a404c5622ed0ca933752a00ce05117727c7d11f05536 | Fake Airbus Job Description PDF |
| 620c51f4376cb79f0109c21971c28661418ae50b119585e3ffdb8011189fcb7b | Fake Ebix Job Description PDF   |
| d1f525eb9347133b92e9558e1413558c8348c0f35a62577f60a5192ba38eb776 | TOTPGuard.zip                   |
| 8e5fc0998838559ca8611e6c03fd998a17ffc2eade24715b2fc3e723c712eb8b | setup.exe.config                |
| eee657ffdb2af8ed6412221e7d5fbf4f5742f2ac2c88f43f12db46af0697de71 | TOTPGuard.dll                   |
| dfa1e3137a032ee8561a1cd5e1a0f71a10bebb36aef7c336c878638a9c1239ee | main.dll                        |
| 3628d13d2f8af7663d58dd1aa352c8f12d12233a7318ee203f01f195573a2ed2 | EbixExam.Desktop.zip            |
| c7ef2ec19d158301773b1590f5b5eeb362a30f725acad8f5b3a230e9f26d14be | EbixExam.Updater.dll            |
| 072744ce205bb89a36e563a86f30df5689e64eee75106b97ce708551c8194bbc | EbixExam.Updater.ServiceHub.dll |

| Domain                                           | Associated Payload              |
| ------------------------------------------------ | ------------------------------- |
| globalitconsultants[.]azurewebsites[.]net        | main.dll                        |
| globalbusiness-checkers-it[.]azurewebsites[.]net | main.dll                        |
| global-check-business-it[.]azurewebsites[.]net   | main.dll                        |
| global-check-itbusiness[.]azurewebsites[.]net    | main.dll                        |
| global-it-checkbusiness[.]azurewebsites[.]net    | main.dll                        |
| global-it-consultants[.]azurewebsites[.]net      | main.dll                        |
| globalit-consultants[.]azurewebsites[.]net       | main.dll                        |
| global-it-checkers[.]azurewebsites[.]net         | main.dll                        |
| business-dns-ns-joiners[.]azurewebsites[.]net    | EbixExam.Updater.ServiceHub.dll |
| ebix-exam-join-from-app[.]azurewebsites[.]net    | EbixExam.Updater.ServiceHub.dll |
| business-joiners-exam[.]azurewebsiets[.]net      | EbixExam.Updater.ServiceHub.dll |
| join-exam-now-ebix[.]azurewebsites[.]net         | EbixExam.Updater.ServiceHub.dll |

| Path/Filename                          | Associated Payload |
| -------------------------------------- | ------------------ |
| \AppData\Local\VirtualStore\result.con | main.dll           |
| \CKAConsent.dll                        | main.dll           |
| \2FAGuard\main.dll                     | TOTPGuard.dll      |
| \2FAGuard\setup.exe.config             | TOTPGuard.dll      |

## Additional Resources

### Yara

[apt_apt35_malware_may26.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/apt_apt35_malware_may26.yar)

[susp_generic_rules_may26.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/susp_generic_rules_may26.yar)
