# Bundled, not fetched

Instrument Sans and Martian Mono, the two faces the muster brand uses. Same
faces as the splash page at the apex domain and the operator console, so the
three surfaces read as one product.

BUNDLED RATHER THAN DOWNLOADED, and that is the whole point. Android can pull
fonts from a provider at runtime, which would save 140 KiB and cost the one
moment that matters: a freshly wiped handset part-way through provisioning has
no Play Services session and frequently no network, and that is exactly when it
renders the enrollment screen. A typeface that arrives late is a screen that
renders in the system fallback on the only device state where a person is
watching it closely.

Three weights, because the design uses three and no more:

    instrument_sans_regular.ttf    400  body text, row values
    instrument_sans_semibold.ttf   600  the headline
    martian_mono_medium.ttf        500  row labels and machine data

Licensed under the SIL Open Font License 1.1; see OFL.txt. Both families are
Google Fonts releases, taken from the weight-split TTF endpoint rather than the
woff2 one, because Android reads TrueType and not woff2.
