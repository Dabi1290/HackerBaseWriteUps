
# Malware signature based detection

```
rule ExampleRule
{
    strings:
        $my_text_string = "qqlvy"
        $my_hex_string = { 62 67 79 69 61  }

    condition:
        $my_text_string or $my_hex_string
}

```


# Web application firewall knowledge

```
SecRule REQUEST_PROTOCOL "@streq HTTP/2.0" \
    "id:1234,phase:1,deny,status:403,msg:'Blocking HTTP/2.0 requests'"
```

```
SecRule REQUEST_METHOD "@streq GET" \
    "id:1234,phase:1,deny,status:403,msg:'Blocking HTTP/2.0 requests'"
```
