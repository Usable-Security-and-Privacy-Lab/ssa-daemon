# Config Parser Documentation

The current edition of the SSA Daemon uses a custom-written YAML parser. 
Past versions used libyaml (`<yaml.h>`), but it resulted in poor performance 
when ran using `valgrind` and required quite a bit of unnecessary boilerplate 
code. It was also a generally untested library at the time, so having our own 
parser allows for us to ensure thorough testing.

The current code related to config file parsing can be found in 
`config_optins.c`, `config_parser.c` and `config.h`. The code is separated into 
these two different .c files to allow for easy addition of valid configuration 
options into the parser. The contents of the files are as follows:

### config_parser.c

This file contains the main bulk of the parser code. It is where errors are 
detected and returned, files are buffered and read character by character using 
`fs_read()`, and a final `global_config` struct is passed back via the 
`parse_config()` function. Any bugs in config parsing will almost always come 
back to this file.

### config_options.c

This file contains the constant array `parser_keys`, which contains a 
**sorted** list of configuration labels along with their associated parsing 
functions. Whenever a label is scanned within the configuration file, the 
parser will check that it has not been read before and execute the function 
associated with the label in this list.


### config.h

This file contains declarations of global const variables that need to be 
shared between `config_parser.c` and `config_options.c`, as well as 
declarations of parsing functions that must be called by the daemon (such 
as `parse_config`).


## Adding a New Label to be Parsed

To add a new valid label to the configuration, four steps are required:

1.  Add the option to the `global_config` struct as an appropriate data type 
    for storing.

2.  Create a new function (usually of the naming form `read_<option_name>`) 
    within config_options.c. This function should return an integer value 
    indicating success (0) or failure (-1), and should accept a `file_stream` 
    pointer and a `global_config` pointer. It should use one of the following 
    functions to read the appropriate information into the `global_config` 
    struct:

    ```c
    int parser_read_string(file_stream *fs, char **str);
    int parser_read_int(file_stream *fs, int *val, int min, int max);
    int parser_read_boolean(file_stream *fs, int *val);
    int parser_read_list(file_stream *fs, char **str_list[]);
    ```

    Note that the address of the appropriate field in the `global_config` 
    struct should be passed in as the second parameter in any of these 
    functions. For examples of this, see the existing functions found in 
    `config_options.c`.

3.  Add the label of your config element, as well as the function label you 
    have just created, into the `parser_keys` list. **MAKE SURE** that you 
    insert it in the correct alphabetical order.

4.  Update the value of the `PARSER_KEY_CNT` macro found within `config.h` to 
    accurately reflect the new size of the `parser_keys` list.

