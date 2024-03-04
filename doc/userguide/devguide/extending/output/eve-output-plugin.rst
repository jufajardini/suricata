EVE JSON Output Plugin
======================

Extensive Event Format (EVE) JSON logs are the main log format for Suricata,
used to output alerts, anomalies, metadata, fileinfo, protocol-specific records
and more through JSON. (Read more: :doc:`../../../output/eve/eve-json-output`)

We provide an EVE Output plugin with Suricata, which can be used to post-
process Suricata's JSON, or to send it to a custom destination.

This section covers the API callbacks for said plugin.

Application
-----------

A common usage for this output plugin would be, for instance, to send Suricata
EVE outputs to a database destination, such as `Redis <https://redis.io/docs/about/>`_.

For Redis, Jason Ish crafted an example: https://github.com/jasonish/suricata-redis-output

API Callbacks
-------------

Registering the plugin with Suricata:
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Declare a `SCPlugin` with the Plugin info - ``name``, ``author``, ``license``,
and ``Init`` function - this last one is where the ``SCEveFileType`` plugin struct
should be initialized.

.. literalinclude:: ../../../../../src/suricata-plugin.h
    :caption: src/suricata-plugin.h - SCPlugin
    :language: c
    :start-at: typedef struct SCPlugin_ {
    :end-at: } SCPlugin;

``SCEveFileType`` will register output name, as well as all callback functions:

    - ``name``: the name of the output which will be used in the eve filetype field
      in ``suricata.yaml`` to enable this output.
    - ``Init``: called when the output is "opened".
    - ``Deinit``: called the output is "closed".
    - ``ThreadInit``: called to initialize per thread data (if threaded).
    - ``ThreadDeinit``: called to deinitialize per thread data (if threaded).
    - ``Write``: called when an EVE record is to be "written".

.. literalinclude:: ../../../../../src/suricata-plugin.h
    :caption: src/suricata-plugin.h - SCEveFileType
    :language: c
    :start-at: typedef struct SCEveFileType_ {
    :end-at: } SCEveFileType;


