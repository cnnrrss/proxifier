# Proxifier

Dump mitmproxy flows to an output file

```
cat > ~/.mitmproxy/config.yaml <<EOF
dump_destination: "$HOME/mitmproxy/site/output.log"
EOF
```

## Usage

```
mitmproxy --mode reverse:https://some-site.com/ -s jsondump.py
```
