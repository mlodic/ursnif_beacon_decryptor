# Ursnif beacon decryptor

Ursnif v.3 aka Dreambot/Gozi/ISFB

This is a simple script that could be used to:
* check if a suspicious URL is correlated to Ursnif activity
* decrypt URL check-in on the fly to get data sent to the C2 server

Usage:
```
python3 ursnif_beacon_decryptor.py -u <url> -k <key>

```

##### Example:
Input:
```
python3 ursnif_beacon_decryptor.py -u "http://qjdyugisselle.club/images/NM_2Ff8mqmMQjmr/c842xf8TIJp_2FlmC5/Ulz244kFh/KMjQpHVvOnBhk6eOvBBW/R_2FCf2Bk9wZXqeGcBS/IAHu5OfIJa7Y941YuvL1XM/i2RXCwmaVXV_2/ByGxravm/Dt1GoxZJ9b2BbnKWLrfphW9/8pKXBhb9Yi/n0AEln6Sc_2BilzFW/k_2B_2Fy1/Q3.avi" -k "10291029JSJUYNHG"
```
Output:
```
[2019-04-15 11:24:25 - INFO] c2 domain: 'qjdyugisselle.club'
[2019-04-15 11:24:25 - INFO] path to analyze: /images/NM_2Ff8mqmMQjmr/c842xf8TIJp_2FlmC5/Ulz244kFh/KMjQpHVvOnBhk6eOvBBW/R_2FCf2Bk9wZXqeGcBS/IAHu5OfIJa7Y941YuvL1XM/i2RXCwmaVXV_2/ByGxravm/Dt1GoxZJ9b2BbnKWLrfphW9/8pKXBhb9Yi/n0AEln6Sc_2BilzFW/k_2B_2Fy1/Q3.avi
[2019-04-15 11:24:25 - INFO] Congrats! decoded data: fjidtflrb=bdaxhhfg&soft=3&version=217173&user=a618b5f78c4ff30be60d08c7ba561278&server=12&id=3274&crc=3&uptime=11
```


We welcome:
* tips on observed different behaviours of the malware
* decryption for other phases of the communication with the C2 infrastructure
* everything that can help to fight this threat

