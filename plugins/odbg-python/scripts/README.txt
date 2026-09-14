One-shot sheduler: .py files here are NOT loaded at startup. Each gets a
"Run: <name>" item in the Plugins menu that imports it on demand and calls
main(odbg) (or main()). The whole python_sdk is available via odbg.

Perfect for disposable helpers: snapshot state, unpack-to-OEP, one-off
searches. Files starting with "_" are ignored. See the example in
../examples_scripts/ (copied here at build time).