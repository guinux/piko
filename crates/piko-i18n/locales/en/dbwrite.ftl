# The errors of piko-db-write, the local database writer.

dbw-error-io-create = failed to create { $path }
dbw-error-io-create-dir = failed to create directory { $path }
dbw-error-io-write = failed to write { $path }
dbw-error-io-rename = failed to rename onto { $path }
dbw-error-io-remove = failed to remove { $path }
dbw-error-io-open = failed to open { $path }
dbw-error-io-stat = failed to stat { $path }
dbw-error-io-sync = failed to flush to disk { $path }
dbw-error-database-locked = unable to lock the database at { $path }; if no package manager is running, remove it
dbw-error-wrong-lock = the lock at { $lock } does not belong to the database at { $dbpath }
dbw-error-temporary-replaced = { $path } was replaced by another file before it could be renamed
dbw-error-record = failed to represent { $path } for rewriting
# $name is quoted, as Rust quotes a string.
dbw-error-invalid-member-name = { $name } does not name a file inside a database entry

# Why a desc or files file cannot be rewritten. $content, $keyword and $value are quoted, as Rust
# quotes a string, except in a %KEYWORD% header.
dbw-record-value-outside-section = line { $line } has no section: { $content }
dbw-record-duplicate-section = section %{ $keyword }% appears more than once, first again at line { $line }
dbw-record-invalid-keyword = { $keyword } cannot be a section keyword
# $reason is a dbw-unrepresentable message.
dbw-record-unrepresentable-value = section %{ $keyword }% cannot hold the value { $value }: { $reason }

# Why a value cannot be written as one value line.
dbw-unrepresentable-empty = an empty line ends a section
dbw-unrepresentable-line-break = a line break would read back as several values
dbw-unrepresentable-nul = a reader of C strings would stop at the NUL
dbw-unrepresentable-section-header = it would read back as a section header
