import urllib.request
c = urllib.request.urlopen('https://example.com').read()

print(c)