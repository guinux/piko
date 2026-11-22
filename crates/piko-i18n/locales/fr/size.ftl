# A number of bytes, in a binary unit.
#
# $value is a number already written: a whole count of bytes, or a number with two decimals
# for a larger unit, with size-decimal-mark between its whole part and its decimals.

size-decimal-mark = {","}
size-bytes = { $value }{" "}o
size-kib = { $value }{" "}Kio
size-mib = { $value }{" "}Mio
size-gib = { $value }{" "}Gio
size-tib = { $value }{" "}Tio
size-pib = { $value }{" "}Pio
size-eib = { $value }{" "}Eio
