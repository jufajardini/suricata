EVE JSON Output
===============

Extensive Event Format (EVE) JSON logs are the main log format for Suricata,
used to output alerts, anomalies, metadata, fileinfo, protocol specific records
and more through JSON. (Read more: :doc:`../../../output/eve/eve-json-output`)

For application layer protocols supported by Suricata, there is native EVE
logging output. To extend Suricata's EVE output, it is possible to use our `EVE
output plugin <https://github.com/OISF/suricata/tree/master/examples/plugins/c-json-filetype#readme>`_.
