rule cutwail2
{
       strings:
               $c1 = { 33 c0 64 03 40 30 8b 40 0c 8b 70 1c ad 8b 40 08 }
       condition:
               all of them
}

rule cutwail
{
       strings:
               $c1 = { 8b 44 24 04 3d fc 00 00 00 }
       condition:
               all of them
}
