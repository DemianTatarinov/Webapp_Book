from flask import Flask, render_template, request, session, copy_current_request_context
from markupsafe import escape as escape_html
from DBcm import UseDatabase, ConnectionError, CredentialsError, SQLError
from checker import check_logged_in
from threading import Thread
from time import sleep

app = Flask(__name__)

app.config['dbconfig'] = {'host': '127.0.0.1',
                          'user': 'vsearch',
                          'password': 'vsearchpasswd',
                          'database': 'vsearchlogDB', }


def search4vowels(phrase: str) -> set:
    """Return any vowels found in a supplied phrase."""
    return set('aeiou').intersection(set(phrase))


def search4letters(phrase: str, letters: str='aeiou') -> set:
    """Return a set of 'letters' found in 'phrase'."""
    return set(letters).intersection(set(phrase))


def search4vowels_and_letters(phrase: str, letters: str='aeiou') -> set:
    """Return a set of vowels and the specified letters found in 'phrase'."""
    return search4vowels(phrase).union(search4letters(phrase, letters))


@app.route('/login')
def do_login() -> str:
    session['logged_in'] = True
    return 'You are now logged in.'


@app.route('/logout')
def do_logout() -> str:
    session.pop('logged_in')
    return 'You are now logged out.'


@app.route('/search4', methods=['POST'])
def do_search() -> 'html':
    """Extract the posted data; perform the search; return results."""

    @copy_current_request_context
    def log_request(req: 'flask_request', res: str) -> None: # type: ignore
        sleep(15)  # This makes log_request really slow...
        with UseDatabase(app.config['dbconfig']) as cursor:
            _SQL = """insert into log
                    (phrase, letters, ip, browser_string, results)
                    values
                    (%s, %s, %s, %s, %s)"""
            browser_string = request.user_agent.string if hasattr(request.user_agent, 'string') else 'Unknown'
            cursor.execute(_SQL, (escape_html(req.form['phrase']),
                                escape_html(req.form['letters']),
                                req.remote_addr,
                                browser_string,
                                res))

    phrase = request.form['phrase']
    letters = request.form['letters']
    title = 'Here are your results:'
    results = search4vowels_and_letters(phrase, letters)
    try:
        t = Thread(target=log_request, args=(request, str(results)))
        t.start()
    except Exception as err:
        print('***** Logging failed with this error:', str(err))
    return render_template('results.html',
                           the_title=title,
                           the_phrase=phrase,
                           the_letters=letters,
                           the_results=results,)



@app.route('/')
@app.route('/entry')
def entry_page() -> 'html':
    """Display this webapp's HTML form."""
    return render_template('entry.html',
                           the_title='Welcome to search4letters on the web!')


@app.route('/viewlog')
@check_logged_in
def view_the_log() -> 'html':
    """Display the contents of the log file as a HTML table."""
    try:
        with UseDatabase(app.config['dbconfig']) as cursor:
            _SQL = """select phrase, letters, ip, browser_string, results
                    from log"""
            cursor.execute(_SQL)
            contents = cursor.fetchall()
        # raise Exception("Some unknown exception.")
        titles = ('Phrase', 'Letters', 'Remote_addr', 'User_agent', 'Results')
        return render_template('viewlog.html',
                               the_title='View Log',
                               the_row_titles=titles,
                               the_data=contents,)
    except ConnectionError as err:
        print('Is your database switched on? Error:', str(err))
    except CredentialsError as err:
        print('User-id/Password issues. Error:', str(err))
    except SQLError as err:
        print('Is your query correct? Error:', str(err))
    except Exception as err:
        print('Something went wrong:', str(err))    
    return 'Error'

app.secret_key = 'YouWillNeverGuessMySecretKey'

if __name__ == '__main__':
    app.run(debug=True)
