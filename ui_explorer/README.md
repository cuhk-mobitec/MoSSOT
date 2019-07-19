# Auto UI Search Using Appium (Part of Oauth Test Project)

## Requirement

- JAVA
- Android SDK
- [appium](http://appium.io/getting-started.html)
- Add aapt to PATH (installed with Android SDK)
- Python modules: [PyMongo], [colorlog], [difflib]

[PyMongo]: https://github.com/mongodb/mongo-python-driver
[uiautomator]: https://github.com/xiaocong/uiautomator#basic-api-usages

Tools might be useful:

- [app-inspector](https://macacajs.github.io/app-inspector/)
- [Inspeckage](https://github.com/ac-pm/Inspeckage)

## Structure:

```
.
├── README.md
├── db
│   └── ...
├── log
│   └── ...
├── conf
│   ├── explorer.xxx.conf        # explorer config for xxx
│   └── template.json           # sample path config for navigator
├── lib
│   ├── __init__.py
│   ├── db.py                   # MongoDB wrapper
│   ├── helper.py               # Helper functions
│   ├── layout.py               # Page and element model
│   ├── emulator.py             # Emulator controller
│   ├── logger.py               # Colorful logger
│   ├── manifest.py             # APK manifest parser
│   ├── smartmonkey.py          # Classes for UI related handling
│   ├── uiaction.py             # Wrapper for navigator
│   └── myexceptions.py         # Custom exceptions
├── batch_explorer.py           # Script for running batch explore
├── explorer_test.py            # Script for running single explore
└── navigator_test.py           # Script for testing Navigator with specified configs
```

## Change Logs

### 2018-04-11 (v4.0)

- Create new `UniqueElement` and `UniquePage` class to model elements and pages. Refactor related code into `layout.py`.
- New emulator controller supporting both Genymotion and Android Emulator. Refactor into `emulator.py`
- Initial version of DFS algorithms in `Explorer`
- Modified and new test scripts, mainly for `Explorer`.


### 2017-01-30 (v3.6)

- Add `wait_for_activities` in `SmartMonkey`.
- Rewrite `better_start_activity` in `SmartMonkey`. Remove the same method in `UIAction`
- Multiple IdP support for `Explorer`
- `SmartMonkey` accept optional argument `app_style` for different strategy. Accepted values: `chinese`, `international`.
- Increase default `max_len` to better support Facebook


### 2017-01-12 (v3.5)

- Navigator return 'Uncertain' when destination of path is not defined.
- Rename `exceptions.py` to `myexceptions.py` to avoid conflicts when `import exceptions`
- Change to `UiAutomator2` and set its timeout configurations in testing scripts.
- Update `home_activity` to config file.

### 2017-12-15 (v3.4)

- Add option for `find_elements_by_keywords` to switch between
  using `UIAutomator` or pure `Xpath1.0` as underlying tool
- Reduce the chance for `ElementInfo` sending repeated requests to Appium
- Add detailed document string to `find_elements_by_keywords`

### 2017-12-04 (v3.2)

- Add IdP support
    - `UIAction` class now take a new optional argument `idp`.
      It must be specified if `config_file` is not provided.
- Add formal option parser to `navigator_test.py`
    - Add `--serial`, `--port` option as in `batch_explorer`
    - Add `--no-reset`, `--quiet` options

### 2017-11-27 (v3.1)

- Add help info to `batch_explorer.py`
- Parallel testing support for batch explore mode
- Bug fix for `aapt`/`adb` commands with apk name containing space

### 2017-11-10 (v3.0)

- Suport `xpath` besides `keyword`
- Scroll to end while finding elements by xpath
- Sort elements by length of text
- Option to set maximum text length of elements
- Batch explorer script

### 2017-7-7

- Remove common.py, change to logger.py and helper.py
- Handle skip_irrelevant calls automatically
- Start activities before each action
- Config json structure change
    - Add origin activities for each path
    - Record home activity
    - Stops can be optional
- Add Stabilizer class and landing action
    - landing() will skip_irrelevant and get home_acitiviy.
    - It's mainly for first time launching.
- **Interface Change Suggestion**:
    - Update all common.xxx function calls to logger.xxx or helper.xxx
    - Remove all skip_irrelevant and start_activity calls,
    only use login, logout and user_info, the rest will be
    handled automatically.
    - Call landing when launching an APP for the first time if needed.