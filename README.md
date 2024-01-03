# ST common data

## Introduction

`st_common_data` is common data that is used in different ST projects.
## Installation

```shell
pip install st_common_data
```

## Usage

```python
from st_common_data.utils.common import (
    is_holiday,
    get_current_eastern_datetime,
    round_half_up_decimal,
    # ....     
)
```

## To update pip package via terminal:

1) Add updates
2) Change version in st_common_data.\__init\__.py
3) Commit changes
4) Run build:
```
python3 -m build
python3 -m pip install --upgrade twine
```

5) Run this command from the same directory where dist directory is located:
```
twine upload --skip-existing dist/*
```