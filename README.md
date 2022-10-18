[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
[![Downloads](https://pepy.tech/badge/sdto)](https://pepy.tech/project/sdto)

# sdto - subdomain takeover finder

Subdomain takeover scanner  
Current count of fingerprints: **80**

[What is subdomain takeover?](https://labs.detectify.com/2014/10/21/hostile-subdomain-takeover-using-herokugithubdesk-more/)


## Supported Services

```
acquia
activecampaign
aftership
agilecrm
aha
airee
anima
announcekit
aws/s3
bigcartel
bitbucket
brightcove
campaignmonitor
canny
cargo
cargocollective
cloudfront
desk
fastly
feedpress
flexbe
flywheel
frontify
gemfury
getresponse
ghost
gitbook
github
hatenablog
helpjuice
helprace
helpscout
heroku
hubspot
intercom
jazzhr
jetbrains
kajabi
kinsta
launchrock
mashery
netlify
ngrok
pagewiz
pantheon
pingdom
proposify
readme
readthedocs
s3bucket
shopify
shortio
simplebooklet
smartjob
smartling
smugmug
sprintful
statuspage
strikingly
surge
surveygizmo
surveysparrow
tave
teamwork
thinkific
tictail
tilda
tumbler
uberflip
unbounce
uptimerobot
uservoice
vend
webflow
wishpond
wix
wordpress
worksites.net
wufoo
zendesk
```
## Installation:


to use as python library
```shell
pip install sdto
```

to use as a CLI tool

```shell
pip install sdto[cli]
```


**or:**
```shell
git clone https://github.com/scanfactory/sdto.git
cd sdto
poetry install
```
## Usage as a CLI tool

Examples:

```shell
python3 -m sdto -t www.domain.com
python3 -m sdto -t www.domain.com -f path/to/custom-fingerprints-file.json
python3 -m sdto -t https://www.domain.com/
python3 -m sdto -t http://www.domain.com/
python3 -m sdto -t www.domain.com --no-ssl
python3 -m sdto -t www.domain.com -v --timeout 30
python3 -m sdto -t www.domain.com -H "user-agent" "your-custom-user-agent" -H "another-header" "header-value"
python3 -m sdto -t www.domain.com -F json
python3 -m sdto -t www.domain.com -o output.txt
python3 -m sdto -t www.domain.com -F json -o output.json
python3 -m sdto -t www.domain.com -F txt -o output.txt
python3 -m sdto -t www.domain.com -p http://127.0.0.1:8080 
python3 -m sdto -l subdomains-list.txt
```

### Docker support

Build the image:

```
docker build -t sdto .
```

Run the container:

```
docker run -it --rm sdto -t www.domain.com -v
```


### Using custom fingerprints

You can specify custom fingerprints file via `-f path/to/file.json` parameter.
The expected json file format:
```json
{
  "AWS/S3": {"pattern": "The specified bucket does not exist"},
  "BitBucket": {"pattern": "Repository not found"},
  "Fastly": {"pattern": "Fastly pattern\\: unknown domain\\:", "process_200": true}
}
```
Note that `pattern` value is expected to be a python regexp.

## Usage as a python library

Example:

```python
import re

from aiohttp import ClientSession
from sdto import check_target, RegexFingerprint


async def main():
    async with ClientSession() as cs:
        fingerprint = await check_target(
            cs=cs,
            target="sub.domain.com",
            ssl=True,
            proxy=None,
            fingerprints=[
                RegexFingerprint(
                    "Github", 
                    re.compile(r"There isn\'t a Github Pages site here\."),
                    process_200=False,
                )
            ]
        )
        if not fingerprint:
            print("No match")
        else:
            print(fingerprint.name)

```
