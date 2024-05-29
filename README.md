  <h2>Guidelines</h2>
  <ol>
      <li><b>[IMPORTANT]</b> Export all your data into a data file for others to use as sample data
        <ul>
          <li>Import the sample data into your own MySQL server and use that for testing</li>
          <li>Make sure that your MySQL server already has a root client using password
            <code>password123</code> and inside it, there's a schema/ database named <code>tastefully</code>
          </li>
        </ul>
      </li>
      <br />  
      <li>Do not commit &amp; push your own virtual environments</li>
      <br />
      <li>
          Always commit &amp; push after each development session
          <ul>
              <li>
                  If you have installed &amp; used any new packages,
                  please update <code>requirements.txt</code> so everyone
                  can run the app smoothly
              </li>
              <li>
                  Note: Only include what you 'pip installed', DO NOT run the
                  command <code>pip freeze > requirements.txt</code> because that will "dirty"
                  our <code>requirements.txt</code><br>
                  <ul>
                    <li style="list-style-type:disc;">
                      All other packages that the installed packages need will be
                      installed once you run <code>pip install -r requirements.txt</code>
                      provided said packages are already within <code>requirements.txt</code>
                    </li>
                  </ul>
              </li>
          </ul>
      </li>
      <br />
      <li>
          Use snake casing for most names &lpar;filenames, folder names,
          variables, functions&rpar;
          <ul>
              <li>For Python classes, use pascal casing</li>
              <li>For HTML, CSS &amp; Javascript, use camel casing</li>
          </ul>
      </li>
      <br />
      <li>
          Prefix HTML template names according to which role can see that
          template
          <ul>
              <li>
                  For members, we&apos;ll assume standard members
                  &lpar;<code>member_</code>&rpar;, use
                  &lpar;<code>pmember_</code>&rpar; for premium members
              </li>
          </ul>
      </li>
      <br />
      <li>
          Refrain from working on someone else&apos;s section unless you
          really think your work fits there
      </li>
      <br />
      <li>
          Please modularise everything into the form of functions for
          reusability &amp; it also helps with readability
      </li>
  </ol>

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
