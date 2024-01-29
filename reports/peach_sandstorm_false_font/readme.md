## IOCs
| Type | Indicator |
| ---- | ---- |
| SHA-256 | 364275326bbfc4a3b89233dabdaf3230a3d149ab774678342a40644ad9f8d614 |
| SHA-1 | ddd18e208aff7b00a46e06f8d9485f81ff4221ea |
| MD5 | 6fd5d31d607a212c6f7651c79e7655a3 |
| Mutex | `864H!NKLNB*x_H?5` |
| Commandline | `SQP's*(58vaP!tF4` argument used for Update and Restart |
| Filename | Maxar.exe |
| Path | `%localappdata%\Temp\Maxar.exe` |
| Path | `%localappdata%\Microsoft\System.exe` |
| Path | `%localappdata%\broker.exe` |
| Path | `%appdata%\host.exe` |
| IP | hxxp://64[.]52[.]80[.]30:8080 |
| Domain | hxxp://digitalcodecrafters[.]com |

### Registry 

- `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`

    - `Value: host.exe Data: %appdata%\host.exe`

    - `Value: broker.exe Data: %localappdata%\broker.exe`

    - `Value: System.exe Data: %localappdata%\Microsoft\System.exe`
