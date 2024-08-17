# Tastefully

## About
Tastefully (Our Web Application) is a platform for users to create and share recipes, 
and sell food bundles into an all in one sustainable meal service. 
Our business model is a subscription plan that provides a 30-day supply 
of sustainable food bundles, including fresh ingredients, delivered directly 
to our users’ home. Subscribers also gain access to exclusive Premium recipes. 
Additionally, our platform features a robust recipe discovery and sharing sections, 
and interactive forums where users can connect and share their culinary creations


<h2>How to Set Up and Use</h2>
<ol>
    <li>In mySQL workbench, create a connection with the following details:<br>
    Name: <code>appsecproj_user</code><br>
    Password: <code>kH40KNgreUpZGPHiZGFoccqPc5E5jciof8dRvsro4tZ5TnSGrl</code><br>
    </li>
    <li>Create a schema <code>tastefully</code></li>
    <li>Run <code>pip install -r requirements.txt</code> to install the required modules</li>
    <li>Run <code>python -u run.py</code> to start the application</li>
</ol>


# TO NOTE

## User Account Management (Zhao Han)

### For creating Admin Accounts:
<ol>
<li>Go to <code>/start</code></li>
<li>Find the masterkey in MySQL workbench, located in the <code>master_key</code> table</li>
<li>Enter the masterkey</li>
<li>Follow the process</li>
</ol>

## Recipes (Miguel)

### Privileges of Each User Group:
**Admins**: CRUD all recipes (Including Private), Access to AI Recipe Creator and Recipe Customiser, and Recipe Dashboard<br>
**Members (Standard)**: CRUD their own recipes (Including Private), Access to AI Recipe Creator and Recipe Customiser<br>
**Members (Premium)**: CRUD their own recipes (Including Private) and can view premium recipes, Access to AI Recipe Creator and Recipe Customiser<br>
**Guest**: Can only view standard recipes

To Note:
Recipe Database Routes are different for each user 



  <h2>Directory guide</h2>
  <p>
      Directories are already created according to different sections,
      please only add files that fit within a certain directory
  </p>
  <p>We can consider different ways to categorise our directories</p>

  <h4>AppSecurityProject &lpar;root directory&rpar;</h4>
  <ul>
      <li>
          Contains our entire project, main concern would be in
          <code>app</code>
          folder
      </li>
      <li><code>run.py</code> Runs our flask app</li>
      <li><code>README.md</code> Outlines what to take note of</li>
      <li>
          <code>requirements.txt</code> Contains all essential packages
          &amp; their version to install &lpar;Use Python 3&period;12 for
          virtual environment&rpar;
      </li>
  </ul>

  <h4>app &lpar;main application directory&rpar;</h4>
  <ul>
      Contains all application related files and folders that we will be
      working on
      <li>
          <code>__init__.py</code> Defines <code>create_app()</code> that
          allows our app to run, acts as mdeium for all imports
      </li>
      <li>
          <code>config.py</code> Defines <code>Config</code> class that
          includes all configurations we are setting for our app
      </li>
      <li>
          <code>forms.py</code> Defines all forms as classes. Create
          separate directory <code>forms</code> if there are too many
          classes
      </li>
      <li>
          <code>models.py</code> Defines all database models/ tables as
          classes. Create separate directory <code>models</code> if we
          have too many models
      </li>
  </ul>

  <h4>templates &lpar;HTML folder&rpar;</h4>
  <ul>
      <li>
          Contains all HTML files to be rendered, mainly separated by user
          roles &lpar;<code>admin</code>, <code>guest</code>,
          <code>member</code>&rpar;
      </li>         
      <li>
          Create new folders for extended categories whenever necessary
      </li>
  </ul>

  <h4>static &lpar;media, css, javascript&rpar;</h4>
  <ul>
      <li>
          Contains all media, css stylesheets &amp; javascript scripts,
          separated into the following directories:
      </li>
      <li>
          <ul>
              <li>audio</li>
              <li>css</li>
              <li>images</li>
              <li>js</li>
              <li>uploads</li>
              <li>videos</li>
          </ul>
      </li>
      <li>
          <code>uploads</code> strictly for files that users upload &amp;
          to be stored. Create new folders to categorise user uploaded
          files. Since we're using a database, there might not be a need
          for this.
      </li>
  </ul>

  <h2>Commands:</h2>
  <ol>
      <li><code>Ctrl + `</code> Open terminal &lpar;VSCode&rpar;, for PyCharm use <code>Alt + F12</code></li>
      <li><code>python.exe -m pip install --upgrade pip</code> Upgarde pip installer</li>
      <li><code>python3.12 -m venv venv</code> Create virtual environment using Python 3.12</li>
      <li><code>venv/Scripts/activate</code> Activate virtual environment</li>
      <li><code>deactivate</code> Deactivate virtual environment</li>
      <li><code>pip list</code> Check installed packages &amp; verisons</li>
      <li><code>pip install -r requirements.txt</code> Install all packages with correct versions from <code>requirements.txt</code></li>
      <li><code>pip freeze &gt; requirements.txt</code> Update dependencies if installed others that are not stated</li>
      <li><code>python -u run.py</code> Run flask application</li>
  </ol>
