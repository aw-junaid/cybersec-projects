## How to use

1. Create a wordlist file:

   ```bash
   echo -e "www\nmail\nadmin\napi\nblog\ntest" > common.txt
   ```
2. Run the tool:

   ```bash
   python3 subenum.py --domain example.com --wordlist common.txt --threads 20
   ```

Output example:

```
[FOUND] api.example.com -> 203.0.113.9
[FOUND] blog.example.com -> 203.0.113.10
[+] Total found: 2
```

