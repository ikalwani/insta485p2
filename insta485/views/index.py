"""Insta485 index (main) view."""

import uuid
import hashlib
import os
import pathlib
import arrow
import flask
import insta485


def hash_password(input_password, salt=None):
    """Help function."""
    algorithm = 'sha512'
    if salt is None:
        salt = uuid.uuid4().hex
    hash_obj = hashlib.new(algorithm)
    password_salted = salt + input_password  # Use input_password here
    hash_obj.update(password_salted.encode('utf-8'))
    password_hash = hash_obj.hexdigest()
    password_db_string = "$".join([algorithm, salt, password_hash])
    return password_db_string


def verify_password(input_password, password_db_string):
    """Verify password."""
    salt = password_db_string.split('$')[1]
    return password_db_string == hash_password(input_password, salt)


@insta485.app.route('/', methods=['GET'])
def show_index():
    """Route."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    logname = flask.session['logname']
    connection = insta485.model.get_db()

    # get list of postID that u want to display on your index page
    # for loop over the list and for each post, u want to display all info
    # related to the post like comments table, likes table and post table
    cur_logged_in_user = connection.execute("""
        SELECT postid
        FROM posts
        WHERE owner = ?
        ORDER BY postid DESC
        """, (logname,))
    post_ids_logged_in_user = [row['postid'] for
                               row in cur_logged_in_user.fetchall()]

    cur_following = connection.execute("""
        SELECT p.postid
        FROM posts p
        JOIN following f ON p.owner = f.username2
        WHERE f.username1 = ?
        ORDER BY p.postid DESC
        """, (logname,))
    post_ids_following = [row['postid'] for
                          row in cur_following.fetchall()]
    all_post_ids = post_ids_logged_in_user + post_ids_following
    all_post_ids = sorted(post_ids_logged_in_user +
                          post_ids_following, reverse=True)

    all_posts_info = []

    for post_id in all_post_ids:

        # Query to fetch post information
        cur_post_info = connection.execute("""
        SELECT p.postid, p.filename, p.created, u.username AS owner,
        u.filename AS owner_img_url
        FROM posts p
        JOIN users u ON p.owner = u.username
        WHERE p.postid = ?
        """, (post_id,))
        post_info = cur_post_info.fetchone()

        post_info['timestamp'] = arrow.get(post_info['created']).humanize()

        # Query to fetch number of likes for the post
        cur_likes_count = connection.execute(
            """
            SELECT COUNT(*) AS like_count
            FROM likes
            WHERE postid = ?
            """, (post_id,))
        post_info['likes'] = cur_likes_count.fetchone()['like_count']
        # Query to fetch comments for the post, ordered by oldest first

        # Query to check if logged user has liked the post
        cur_liked_user = connection.execute(
            """
                SELECT count(*) AS count
                FROM likes
                WHERE owner = ? AND postid = ?
                """,
            (logname, post_id, )
        )
        post_info['liked_by_logname'] = cur_liked_user.fetchone()['count'] != 0
        cur_comments = connection.execute("""
            SELECT c.*, u.filename AS commenter_img_url
            FROM comments c
            JOIN users u ON c.owner = u.username
            WHERE c.postid = ?
            ORDER BY c.created ASC
            """, (post_id,))
        post_info['comments'] = cur_comments.fetchall()

        all_posts_info.append(post_info)

    context = {
        'logname': logname,
        'posts': all_posts_info
    }
    return flask.render_template('index.html', **context)


@insta485.app.route('/accounts/', methods=['GET'])
def accounts():
    """Display /accounts/ route."""
    if 'logname' not in flask.session:
        return flask.render_template('login.html')
    return flask.redirect(flask.url_for('show_index'))


@insta485.app.route('/accounts/login/', methods=['GET'])
def login():
    """Display login page."""
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('show_index'))

    # Render the login template
    return flask.render_template('login.html')


@insta485.app.route('/accounts/logout/', methods=['POST'])
def logout():
    """Display / route."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    flask.session.clear()
    return flask.redirect(flask.url_for('login'))


@insta485.app.route('/accounts/create/', methods=['GET'])
def create():
    """Create."""
    if 'logname' in flask.session:
        return flask.redirect(flask.url_for('edit'))
    return flask.render_template('create.html')


@insta485.app.route('/accounts/edit/', methods=['GET'])
def edit():
    """Edit."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('show_index'))

    connection = insta485.model.get_db()
    logname = flask.session['logname']

    cur = connection.execute(
        "SELECT fullname, email, filename "
        "FROM users "
        "WHERE username = ? ",
        (logname,)
    )
    res = cur.fetchall()
    print(res[0]['filename'])
    context = {
        "fullname": res[0]['fullname'],
        "email": res[0]['email'],
        "filename": res[0]['filename'],
        "logname": logname
    }
    return flask.render_template('edit.html', **context)


@insta485.app.route('/accounts/password/', methods=['GET'])
def password_user():
    """Password."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))

    logname = flask.session['logname']
    return flask.render_template("password.html", logname=logname)


@insta485.app.route('/accounts/delete/', methods=['GET'])
def delete():
    """Delete."""
    logname = flask.session['logname']
    return flask.render_template('delete.html', logname=logname)


@insta485.app.route('/accounts/auth/', methods=['GET'])
def auth():
    """Auth."""
    if 'logname' not in flask.session:
        flask.abort(403)
    return '', 200


@insta485.app.route('/explore/', methods=['GET'])
def explore():
    """Explore."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for("show_index"))
    logname = flask.session['logname']
    connection = insta485.model.get_db()
    cur = connection.execute(
        """
        SELECT u.username, u.filename
        FROM users u
        LEFT JOIN following f ON u.username = f.username2 AND f.username1 = ?
        WHERE f.username1 IS NULL AND u.username != ?
        """,
        (logname, logname)
    )
    users_not_followed = cur.fetchall()
    context = {
        'users_not_followed': users_not_followed,
        # 'users': result,
        'logname': logname,
    }
    return flask.render_template('explore.html', **context)


@insta485.app.route('/uploads/<path:filename>')
def download_file(filename):
    """Download filename."""
    return flask.send_from_directory(insta485.app.config['UPLOAD_FOLDER'],
                                     filename, as_attachment=True)


@insta485.app.route('/users/<user_url_slug>/', methods=['GET'])
def users(user_url_slug):
    """Users."""
    print(flask.session)
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for("login"))
    # connection = insta485.model.get_db()
    cus = insta485.model.get_db().execute(
        "SELECT username "
        "FROM users "
        "WHERE username = ? ",
        (user_url_slug,)
    )
    # users_sql = cus.fetchall()
    if not cus.fetchall():
        flask.abort(404)

    logname = flask.session['logname']

    # Check if the logged-in user is following this user
    cursor = insta485.model.get_db().execute(
        "SELECT username1, username2 "
        "FROM following "
        "WHERE username1 = ? AND username2 = ?",
        (logname, user_url_slug)
    )
    following = cursor.fetchall()

    full = None
    number_posts = 0
    number_of_following = 0
    number_of_followers = 0
    posts = []

    curr = insta485.model.get_db().execute(
            "SELECT postid, filename "
            "FROM posts "
            "WHERE owner = ?",
            (user_url_slug,)
        )
    posts = curr.fetchall()
    number_posts = len(posts)

    fol = insta485.model.get_db().execute(
            "SELECT COUNT(username1) AS num_followers "
            "FROM following "
            "WHERE username2 = ?",
            (user_url_slug,)
        )
    number_of_followers = fol.fetchone()['num_followers']

    follow = insta485.model.get_db().execute(
        "SELECT COUNT(username2) AS num_following "
        "FROM following "
        "WHERE username1 = ?",
        (user_url_slug,)
    )

    number_of_following = follow.fetchone()['num_following']

    name = insta485.model.get_db().execute(
        "SELECT fullname "
        "FROM users WHERE username = ?",
        (user_url_slug,)
    )
    full = name.fetchone()['fullname']

    context = {
        'username': user_url_slug,
        'fullname': full,
        'number_of_posts': number_posts,
        'num_followers': number_of_followers,
        'num_following': number_of_following,
        'posts': posts,
        'logname': logname,
        'log_following': following,
    }
    return flask.render_template("user.html", **context)


@insta485.app.route('/users/<user_url_slug>/followers/', methods=['GET'])
def followers(user_url_slug):
    """Followers."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    logname = flask.session['logname']

    connection = insta485.model.get_db()
    cursor = connection.execute(
        "SELECT following.username1, users.filename "
        "FROM following "
        "INNER JOIN users "
        "ON following.username1 = users.username "
        "WHERE following.username2 = ?",
        (user_url_slug,)
    )
    followers_data = cursor.fetchall()

    follower_info = []

    for follower in followers_data:
        follower_username = follower['username1']
        filename = follower['filename']

        fol = connection.execute(
            "SELECT COUNT(*) AS following "
            "FROM following "
            "WHERE username1 = ? AND username2 = ?",
            (logname, follower_username)
        )
        following_sql = fol.fetchone()['following']

        relationship = ''
        if following_sql:
            relationship = 'following'
        elif logname != follower_username:
            relationship = 'not following'

        # Append follower information to the list
        follower_info.append({
            'username': follower_username,
            'filename': filename,
            'relationship': relationship
        })

    return flask.render_template('followers.html',
                                 follower_info=follower_info, logname=logname)


@insta485.app.route('/users/<user_url_slug>/following/', methods=['GET'])
def following_user(user_url_slug):
    """Follow."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for('login'))
    logname = flask.session['logname']

    connection = insta485.model.get_db()
    cursor = connection.execute(
        "SELECT following.username2, users.filename "
        "FROM following "
        "INNER JOIN users "
        "ON following.username2 = users.username "
        "WHERE following.username1 = ?",
        (user_url_slug,)
    )
    following_data = cursor.fetchall()

    following_info = []

    for followed_user in following_data:
        followed_username = followed_user['username2']
        filename = followed_user['filename']

        fol = connection.execute(
            "SELECT COUNT(*) AS following "
            "FROM following "
            "WHERE username1 = ? AND username2 = ?",
            (logname, followed_username)
        )
        follow = fol.fetchone()['following']

        relationship = ''
        if follow:
            relationship = 'following'
        elif logname != followed_username:
            relationship = 'not following'

        # Append followed user information to the list
        following_info.append({
            'username': followed_username,
            'filename': filename,
            'relationship': relationship
        })

    return flask.render_template('following.html', following_in=following_info,
                                 logname=logname)


@insta485.app.route('/posts/<postid_url_slug>/', methods=['GET'])
def show_post(postid_url_slug):
    """Display a single post and its details."""
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for("login"))

    logname = flask.session['logname']

    connection = insta485.model.get_db()
    cur_post_info = connection.execute(
        """
        SELECT p.postid, p.filename, p.created, u.username AS owner,
        u.filename AS owner_img_url
        FROM posts p
        JOIN users u ON p.owner = u.username
        WHERE p.postid = ?
        """, (postid_url_slug,)
    )
    post_info = cur_post_info.fetchone()
    post_info['timestamp'] = arrow.get(post_info['created']).humanize()

    is_post_owner = logname == post_info['owner']

    # Query to fetch number of likes for the post
    cur_likes_count = connection.execute(
        """
        SELECT COUNT(*) AS like_count
        FROM likes
        WHERE postid = ?
        """, (postid_url_slug,))
    post_info['likes'] = cur_likes_count.fetchone()['like_count']

    cur_liked_user = connection.execute(
        """
        SELECT count(*) AS like_count
        FROM likes
        WHERE owner = ? AND postid = ?
        """,
        (logname, postid_url_slug, )
    )
    like_count = cur_liked_user.fetchone()['like_count']
    post_info['liked_by_logname'] = like_count != 0

    cur_comments = connection.execute("""
        SELECT commentid, text, owner
        FROM comments
        WHERE postid = ?
        ORDER BY created ASC
        """, (post_info["postid"],))
    comments = cur_comments.fetchall()

    context = {
        'logname': logname,
        'post': post_info,
        'comments': comments,
        'is_post_owner': is_post_owner,
    }
    return flask.render_template('post.html', **context)


@insta485.app.route('/likes/', methods=['POST'])
def show_likes():
    """Get likes."""
    connection = insta485.model.get_db()
    logname = flask.session['logname']

    operation = flask.request.form['operation']
    postid = flask.request.form['postid']
    target = flask.request.args.get('target', '/')
    if not target:
        target = flask.url_for('show_index')

    if operation == 'like':
        cur = connection.execute(
            """
            SELECT likeid AS count
            FROM likes
            WHERE owner = ? AND postid = ?
            """,
            (logname, postid, )
        )
        result = cur.fetchall()
        if len(result) == 0:
            connection.execute(
                """
                INSERT INTO likes (owner, postid)
                VALUES (?, ?)
                """, (logname, postid)
            )
        else:
            flask.abort(409)
        return flask.redirect(target)

    if operation == 'unlike':
        cur = connection.execute(
            """
            SELECT likeid AS count
            FROM likes
            WHERE owner = ? AND postid = ?
            """,
            (logname, postid, )
        )
        result = cur.fetchall()
        if len(result) > 0:
            connection.execute(
                """
                DELETE FROM likes WHERE owner = ? AND postid = ?
                """, (logname, postid)
            )
        else:
            return flask.abort(409)
    return flask.redirect(target)


@insta485.app.route('/comments/', methods=['POST'])
def show_comments():
    """Show comments."""
    connection = insta485.model.get_db()
    logname = flask.session['logname']

    operation = flask.request.form.get('operation')
    target = flask.request.args.get('target', '/')

    postid = flask.request.form.get('postid')
    commentid = flask.request.form.get('commentid')
    text = flask.request.form.get('text')

    if target is None:
        return flask.redirect(flask.url_for('show_index'))

    if not target:
        target = flask.url_for('show_index')
    return_value = None

    if operation == 'create':
        if not text:
            flask.abort(400)
        cur = connection.execute(
                "INSERT INTO comments(owner, postid, text) "
                "VALUES (?, ?, ?) ",
                (logname, postid, text,)
            )
        return_value = flask.redirect(target)

    elif operation == 'delete':
        cur = connection.execute(
            "SELECT * FROM comments WHERE commentid = ?",
            (commentid,)
        )
        comment_owner = cur.fetchone()
        if comment_owner and comment_owner['owner'] != logname:
            flask.abort(403)
            # User owns the comment, proceed with deletion
        else:
            connection.execute(
                "DELETE FROM comments WHERE commentid = ?", (commentid,))
            return flask.redirect(target)
    return return_value


@insta485.app.route('/posts/', methods=['POST'])
def show_posts():
    """Show posts."""
    connection = insta485.model.get_db()
    if 'logname' not in flask.session:
        return flask.redirect(flask.url_for("login"))
    logname = flask.session['logname']

    operation = flask.request.form.get('operation')
    postid = flask.request.form.get('postid')
    target = flask.request.args.get('target', None)

    if target is None:
        target = flask.url_for('users', user_url_slug=logname)

    if operation == 'create':
        fileobj = flask.request.files.get("file")
        if fileobj and fileobj.filename == '':
            flask.abort(400)

        stem = uuid.uuid4().hex
        suffix = pathlib.Path(fileobj.filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"

        path = pathlib.Path(insta485.app.config["UPLOAD_FOLDER"]) \
            / uuid_basename

        fileobj.save(path)

        connection.execute(
                "INSERT INTO posts(filename, owner) "
                "VALUES (?, ?) ",
                (uuid_basename, logname,)
            )
        return flask.redirect(target)

    if operation == 'delete':
        cur = connection.execute(
            "SELECT owner, filename FROM posts WHERE postid = ?",
            (postid,)
        )
        post = cur.fetchone()
        if not post:
            flask.abort(400)  # Post not found

        # Delete the image file associated with the post from the filesystem
        filename = post['filename']
        path = os.path.join(insta485.app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(path):
            os.remove(path)

        # Delete all related data from the database
        connection.execute(
            "DELETE FROM posts WHERE postid = ?",
            (postid,)
        )
        connection.execute(
            "DELETE FROM likes WHERE postid = ?",
            (postid,)
        )
        connection.execute(
            "DELETE FROM comments WHERE postid = ?",
            (postid,)
        )

        return flask.redirect(target)
    return_valeu = None
    return return_valeu


@insta485.app.route('/following/', methods=['POST'])
def show_following():
    """Following."""
    connection = insta485.model.get_db()
    logname = flask.session['logname']

    operation = flask.request.form.get('operation')
    username = flask.request.form.get('username')
    target = flask.request.args.get('target', '/')

    if target is None:
        return flask.redirect(flask.url_for('show_index'))

    if operation == 'follow':
        if username == logname:
            flask.abort(400)

        # check if the user is already following the target user
        cur = connection.execute(
            "SELECT COUNT(*) AS count "
            "FROM following "
            "WHERE username1 = ? AND username2 = ?",
            (logname, username)
        )
        result = cur.fetchone()
        if result['count'] > 0:
            flask.abort(409)

        connection.execute(
            "INSERT INTO following (username1, username2) "
            "VALUES (?, ?)",
            (logname, username)
        )

    elif operation == 'unfollow':
        if username == logname:
            flask.abort(400)

        # check if the user is not following the target user
        cur = connection.execute(
            "SELECT COUNT(*) AS count "
            "FROM following "
            "WHERE username1 = ? AND username2= ?",
            (logname, username)
        )
        result = cur.fetchone()
        if result['count'] == 0:
            flask.abort(409)

        connection.execute(
            "DELETE FROM following WHERE username1 = ? AND username2 = ?",
            (logname, username)
        )
    return flask.redirect(target)


@insta485.app.route('/accounts/', methods=['POST'])
def accounts_post():
    """Display /accounts/ route."""
    connection = insta485.model.get_db()
    operation = flask.request.form['operation']
    target = flask.request.args.get('target', '/')
    if operation == 'login':
        return handle_login(connection, target)

    if operation == 'create':
        return handle_create_user(connection, target)

    if operation == 'delete':
        return handle_delete_user(connection, target)

    if operation == 'edit_account':
        return handle_edit_account(connection, target)

    if operation == 'update_password':
        if 'logname' not in flask.session:
            flask.abort(403)
        logname = flask.session['logname']
        password = flask.request.form['password']
        new_password1 = flask.request.form['new_password1']
        new_password2 = flask.request.form['new_password2']

        if len(flask.request.form['password']) == 0 or len(new_password1) == 0:
            flask.abort(400)
        if len(new_password2) == 0:
            flask.abort(400)

        cur = connection.execute(
            "SELECT * FROM users"
            " WHERE username = ?",
            (logname, )
        )
        database_user = cur.fetchone()
        if database_user is None:
            flask.abort(403)

        if not verify_password(password, database_user['password']):
            flask.abort(403)

        if new_password1 != new_password2:
            flask.abort(401)

        hashed_new_password = hash_password(new_password1)
        connection.execute(
            "UPDATE users SET password = ?"
            " WHERE username = ?",
            (hashed_new_password, logname)
        )
        return flask.redirect(target)
    return_value = None
    return return_value


def handle_login(connection, target):
    """Login logic."""
    username = flask.request.form['username']
    password_i = flask.request.form['password']
    if len(username) == 0 or len(password_i) == 0:
        flask.abort(400)
    cur = connection.execute(
        "SELECT * FROM users "
        "WHERE username = ?",
        (username, )
    )
    database_user = cur.fetchone()
    if database_user is None:
        flask.abort(403)
    if not verify_password(password_i, database_user['password']):
        flask.abort(403)
    flask.session['logname'] = database_user['username']
    flask.session['fullname'] = database_user['fullname']
    return flask.redirect(target)


def handle_create_user(connection, target):
    """Hnalde create."""
    username = flask.request.form['username']
    password_i = flask.request.form['password']
    fullname = flask.request.form['fullname']
    email = flask.request.form['email']
    fileobj = flask.request.files.get('file')

    stem = uuid.uuid4().hex
    suffix = pathlib.Path(fileobj.filename).suffix.lower()
    uuid_basename = f"{stem}{suffix}"

    # Save to disk
    path = f"{insta485.app.config['UPLOAD_FOLDER']}/{uuid_basename}"
    fileobj.save(path)

    if len(username) == 0 or len(password_i) == 0 or fileobj is None:
        flask.abort(400)
    if len(fullname) == 0 or len(email) == 0 or fileobj is None:
        flask.abort(400)

    cur = connection.execute(
        "SELECT * FROM users "
        "WHERE username = ?",
        (username, )
    )
    database_user = cur.fetchone()
    if database_user is not None:
        flask.abort(409)
    hashed_password = hash_password(password_i)
    connection.execute(
        "INSERT INTO users(username, fullname, email, filename, password)"
        "VALUES (?, ?, ?, ?, ?)",
        (username, fullname, email, uuid_basename, hashed_password)
    )

    flask.session['logname'] = username
    flask.session['fullname'] = fullname
    return flask.redirect(target)


def handle_delete_user(connection, target):
    """Delete user."""
    if 'logname' not in flask.session:
        flask.abort(403)
    logname_delete = flask.session['logname']

    user_sql = connection.execute(
        "SELECT filename FROM users WHERE username = ?",
        (logname_delete,)
    )
    user = user_sql.fetchone()

    post_sql = connection.execute(
        "SELECT filename FROM posts WHERE owner = ?",
        (logname_delete,)
    )
    posts = post_sql.fetchall()

    for post in posts:
        filename = post['filename']
        path = os.path.join(insta485.app.config["UPLOAD_FOLDER"], filename)
        if os.path.exists(path):
            os.remove(path)

    if user is None:
        flask.abort(400)

    connection.execute(
        "DELETE FROM users WHERE username = ?",
        (logname_delete, )
    )
    # Delete the image file associated with the user
    filename = user['filename']
    path = os.path.join(insta485.app.config["UPLOAD_FOLDER"], filename)
    if os.path.exists(path):
        os.remove(path)

    flask.session.clear()
    return flask.redirect(target)


def handle_edit_account(connection, target):
    """Handle edit."""
    if 'logname' not in flask.session:
        flask.abort(403)
    user = flask.session['logname']
    fullname = flask.request.form.get('fullname')
    email = flask.request.form.get('email')
    fileobj = flask.request.files['file']
    print(user)
    print(fullname)
    print(email)

    if len(fullname) == 0 or len(email) == 0:
        flask.abort(400)

    if fileobj:
        stem = uuid.uuid4().hex
        suffix = pathlib.Path(fileobj.filename).suffix.lower()
        uuid_basename = f"{stem}{suffix}"

        path = insta485.app.config["UPLOAD_FOLDER"]/uuid_basename
        fileobj.save(path)
        connection.execute(
            "UPDATE users SET fullname = ?, email = ?,"
            "filename = ? WHERE username = ?",
            (fullname, email, uuid_basename, user)
        )
    else:
        connection.execute(
            "UPDATE users SET fullname = ?, email = ? WHERE username = ?",
            (fullname, email, user)
        )

    flask.session["fullname"] = fullname
    return flask.redirect(target)


@insta485.app.route('/uploads/<filename>')
def get_uploaded_file(filename):
    """_summary."""
    if 'logname' not in flask.session:
        flask.abort(403)
    file_path = insta485.app.config["UPLOAD_FOLDER"] / filename

    if not file_path.exists():
        flask.abort(404)

    return flask.send_file(file_path)
