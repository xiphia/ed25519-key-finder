# Ed25519 Key Finder

Search Ed25519 key pair that public key matches a specified condition.

## Usage
```shell
key-finder [<flags>] <condition>
```

`condition`: Regexp string in Go (e.g. `(?i)test`)

`flags`:
* `--comment`, `-c`
  * Comment for key. Default value is `${USERNAME}@${HOSTNAME}`.
* `--limited`, `-l`
  * Number of key you want to find. Default value is `1`.
* `--unlimited`, `-u`
  * If set this option, this will search key pairs until you stop. Ignores `--limited` option.
* `--parallel`, `-p`
  * Concurrency of key pair search. Default value is `1`.

Key pair(s) will be output into current directory as `id_25519_${N}` and `id_25519_${N}.pub`.

## Example
### Machine
* CPU
  * AMD Ryzen(TM) 9 5950X (16C32T, Base: 3.4GHz, Boost: 4.9GHz)
* OS
  * Windows 10 Pro 64bit

### Result
```shell
> .\key-finder.exe "(?i)[/+]test$" -l 10 -p 8
2021/08/11 23:15:15 Start ed25519 key search
2021/08/11 23:15:53 Found: AAAAC3NzaC1lZDI1NTE5AAAAIDZ27/6Ovkgku8AjwS1qrR/SNOxgzjOWhyqvGTK+TesT
2021/08/11 23:23:29 Found: AAAAC3NzaC1lZDI1NTE5AAAAIIMm63lmXLYBa/lT7A5stgbKjqhbGSWiHBE5pdA+TeST
2021/08/11 23:24:53 Found: AAAAC3NzaC1lZDI1NTE5AAAAIPjTaGWMvPfDITluqN190RN2EwKeEmtudno4k8r+TeST
2021/08/11 23:25:16 Found: AAAAC3NzaC1lZDI1NTE5AAAAIL5aNMbmlSkICWo6PpjKTKHM3+qk90D6DUxB4ts/test
2021/08/11 23:31:51 Found: AAAAC3NzaC1lZDI1NTE5AAAAIKlDC1+Y77JowlDJJ1Kg83zW+sBQYyaNVSSKI+l/test
2021/08/11 23:35:54 Found: AAAAC3NzaC1lZDI1NTE5AAAAIIabfEjM58j/zRCxmavdqUitK+MznGJSpHlhuZ3/teSt
2021/08/11 23:36:12 Found: AAAAC3NzaC1lZDI1NTE5AAAAIGFd6ahxRSm5CygPN3+vojlD3VxlC+Sykm2T88q/teSt
2021/08/11 23:36:20 Found: AAAAC3NzaC1lZDI1NTE5AAAAIDGVTXosTm7vBB/PJnRboHBEFB6p7xCCXE7A8PV+tesT
2021/08/11 23:41:06 Found: AAAAC3NzaC1lZDI1NTE5AAAAIAdkzRRpnagycCdzbQlU8VmnhhL/0ak3w5emdjw+tEsT
2021/08/11 23:44:48 Found: AAAAC3NzaC1lZDI1NTE5AAAAILclbB6+ciue5aeJLiteoXCnqmHKnYI+WlS8VJZ+TesT
2021/08/11 23:44:48 Time: 1772 sec
2021/08/11 23:44:48 Total Generated Pairs: 354195355 pairs
2021/08/11 23:44:48 Throughput: 199829 pairs/sec
2021/08/11 23:44:48 Complete ed25519 key search
```

## Reference
* https://qiita.com/umihico/items/c99b41c818c13531f83c
