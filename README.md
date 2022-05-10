# ST common data

## Introduction

`st_common_data` is common data that is used in different ST projects.
## Installation

```shell
pip install st_common_data
```

## Usage

```python
from st_common_data.nyse_holidays import NYSE_HOLIDAYS
from st_common_data.utils import (
    is_holiday,
    get_current_eastern_datetime,
    round_half_up_decimal,
    # ....     
)
```

## To update pip package via terminal:

```
python3 -m build
python3 -m pip install --upgrade twine
```

Run this command from the same directory where dist directory is located:
```
twine upload dist/*
```