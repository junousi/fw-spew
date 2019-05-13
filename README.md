# fw-spew

Spew out some firewall rules.

Input and usage should be something like:

```
$ cat test.csv
13.33.101.81/32,86.50.31.216/32,tcp,80 443 8080
5.6.7.8/32,86.50.31.216/32,tcp,1234
86.50.31.216/32,13.33.101.81/24,tcp,80 443 8080
1.2.3.4/16,13.33.101.81/24,tcp,80 443 8080
$ python csv2fw.py -f test.csv -t prefix-term-
```
