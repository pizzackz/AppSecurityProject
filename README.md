## Setting up a virtual environment (VS Code)
1. Open Terminal by pressing ```Ctrl + ` ```
2. (Optional) Upgrade pip by typing ```python.exe -m pip install --upgrade pip```
2. Create virtual environment by typing ```python -m venv venv``` (You can name your virtual environment wtv you want by replacing the 2nd 'venv')
3. Click on 'Yes' on the bottom right if it says that a new environment has been created ...
4. Whenever you want to run the project in the virtual environment,
- Type ```venv/Scripts/activate``` if you have 'Scripts folder in your virtual environment folder
- Type ```venv/bin/activate``` if you have 'bin' folder in your virtual environment folder
- If you renamed your virtual environment, replace the 'venv' part with whatever you renamed it as
6. Whenever you want to stop running in the virtual environment, type ```deactivate```

## Installing necessary packages
Since there will be a 'requirements.txt' file, holding all the packages required to install, please do:
- ```pip list``` to check whether you have the packages installed and the correct versions
- ```pip install -r requirements.txt``` to install all the packages with the specified version from the file itself
  - If you ever want to update the packages required, type ```pip freeze > requirements.txt```

## Running the Flask application (VS Code)
- Just move your cursor to the top right hand side of VS Code and click on the run icon while you're in the ```__init__.py``` file
- If you ever want to manually run your flask application in the terminal, do any of the following:
  - ```python -u __init__.py``` (recommended)
  - ```flask run``` while the current folder is the main directory containing all the folders and files
 
## Commands for lazy people:
1. ```Ctrl + ` ``` Open terminal
2. ```python.exe -m pip install --upgrade pip``` Upgrade pip installer
3. ```python -m venv venv``` Create virtual environment
4. ```venv/Scripts/activate``` or ```venv/bin/activate``` Activate virtual environment
5. ```deactivate``` Deactivate virtual environment
6. ```pip list``` Check installed packages & versions
7. ```pip install -r requirements.txt``` Install all packages with correct versions
8. ```pip freeze > requirements.txt``` Update packages if installed others that are not stated
9. ```python -u __init__.py``` (recommended) or ```flask run``` Run flask application
