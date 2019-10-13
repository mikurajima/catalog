#!/usr/bin/env python3
# -*- coding:utf-8 -*-
import string
import random
from httplib2 import Http
import requests
from flask import session as login_session
from flask import make_response
import httplib2
from oauth2client.client import FlowExchangeError
from oauth2client.client import flow_from_clientsecrets
from flask_httpauth import HTTPBasicAuth
import json
from datetime import datetime
from models import Base, Items, User, Category
from sqlalchemy.orm import sessionmaker
from sqlalchemy import create_engine, asc, desc
from flask import Flask, render_template, request, redirect, jsonify, url_for
from flask import flash
app = Flask(__name__)
app.secret_key = 'hogehoge'

auth = HTTPBasicAuth()

# Connect to Database and create database session
dialect = "mysql"
driver = "pymysql"
username = "grader"
password = "Shinsaku050$"
host = "127.0.0.1"
database = "udacity1"
charset_type = "utf8"
db_url = "{}+{}://{}:{}@{}/{}?charset={}".format(
    dialect, driver, username, password, host, database, charset_type)
engine = create_engine(db_url, echo=True)
Base.metadata.bind = engine
DBSession = sessionmaker(bind=engine)
session = DBSession()


# authorization
def createUser(login_session):
    newUser = User(name=login_session['username'], email=login_session[
                   'email'], picture=login_session['picture'])
    session.add(newUser)
    session.commit()
    user = session.query(User).filter_by(email=login_session['email']).one()
    return user.id


def getUserInfo(user_id):
    user = session.query(User).filter_by(id=user_id).one()
    return user
    user_id = getUserID(login_session['email'])
    if not user_id:
        user_id = createUser(login_session)
    login_session['user_id'] = user_id


def getUserID(email):
    try:
        user = session.query(User).filter_by(email=email).one()
        return user.id
    except:
        return None


# JSON APIs to view Restaurant Information
@app.route('/catalog/JSON')
def catelogJSON():
    flash("JSON")
    categories = session.query(Category).all()
    all_json_data = []
    num = 0
    for category in categories:
        category_id = category.id
        category_dict = category.serialize
        items = session.query(Items).filter(
            Items.category_id == category_id).all()
        category_dict['items'] = [item.serialize for item in items]
        all_json_data.append(category_dict)
    final_json_data = {}
    final_json_data["category"] = all_json_data
    return jsonify(final_json_data)


# Show top page
@app.route('/')
def showTop():
    category_list = session.query(Category.category_name).order_by(
        asc(Category.category_name)).all()
    item_name_w_category = session.query(
        Items.item_name,
        Category.category_name).join(
        Category, Items.category_id == Category.id).order_by(
        desc(Items.registered_at)).limit(10)
    print(type(item_name_w_category))
    if 'username' not in login_session:
        print('you are not login')
        return render_template(
            'index.html', category_list=category_list,
            item_name_w_category=item_name_w_category)
    else:
        print('you are login')
        return render_template(
            'indexLogin.html',
            category_list=category_list,
            item_name_w_category=item_name_w_category)


# Show all items that belongs to the spesific category
@app.route('/catalog/<string:category>/items')
def items(category):
    if request.method == 'POST':
        newItem = Items(
            item_name=request.form['name'], registered_at=str(datetime.now()))
        session.add(newItem)
        flash('New Item {} Successfully Created'.format(newItem.item_name))
        session.commit()
        return redirect(url_for('showTop'))
    else:
        category_list = session.query(Category.category_name).all()
        category = session.query(Category.id, Category.category_name).filter(
            Category.category_name == category).first()
        items = session.query(Items, Category.category_name).join(
            Items, Items.category_id == Category.id).filter(
                Items.category_id == category.id).all()
        num_items = session.query(Items.item_name).filter(
            Items.category_id == category.id).count()
        if 'username' not in login_session:
            print('you are not login')
            return render_template(
                'items_in_category.html', items=items,
                category_list=category_list,
                category=category.category_name, num_items=num_items)
        else:
            print('you are login')
            return render_template(
                'items_in_categoryLogin.html',
                items=items,
                category_list=category_list,
                category=category.category_name, num_items=num_items)


# Create a new categories
# login is required
@app.route('/category/new', methods=['GET', 'POST'])
def newCategory():
    if 'username' not in login_session:
        # check if user is in login session.
        print('you are not login')
        return redirect(url_for('showTop'))
    if request.method == 'POST':
        print("POST with logined state")
        category_names = session.query(Category.category_name).order_by(
            asc(Category.category_name)).all()
        # after enter category name that user wants to newly register
        if request.form['category_name']:
        #if category name is not empty
            category_name_canditate = request.form['category_name']

            same_category_name = session.query(Category.category_name).filter(
                Category.category_name == category_name_canditate).first()
            print(type(same_category_name))

            if same_category_name is not None:
            # if same_category_name != NONE:
            # if newly registering category name is already in db.
                print('###########################################################')
                error_msg = "{} is already registred".format(
                    category_name_canditate)
                print(error_msg)

                if category_names == []:
                    category_names = "No category is registered yet."
                return render_template(
                    'reg_category.html',
                    category_names=category_names,
                    error_msg=error_msg)

        # ここから下の行を試しに、インデント１つ左に動かしてみる。
        # if the newly registering category name does not exit in db.
            else:
                newItem = Category(
                    category_name=request.form[
                    'category_name'], registered_at=str(datetime.now()))
                session.add(newItem)
                flash('New Item {} Successfully Created'.format(
                    newItem.category_name))
                session.commit()
                return redirect(url_for('newCategory'))
        else:
        #if category_name is empty
            error_msg = 'You have entered nothing. \
                Please enter category name that you would like to register'
            return render_template(
                'reg_category.html',
                category_names=category_names,
                error_msg=error_msg)
    else:
        print("GET with loggedin state")
        category_names = session.query(Category.category_name).order_by(
            asc(Category.category_name)).all()
        if category_names == []:
            category_names = str("No category is registered yet.")
        return render_template(
            'reg_category.html', category_names=category_names)



# @app.route('/catalog/<string:category>/delete', methods=['GET', 'POST'])
@app.route('/category/delete', methods=['GET', 'POST'])
def deleteCategory():
# delete category
# if there are no items using the category name, then delete
# if there are some items using the cateory name, then raise caution
    if 'username' not in login_session:
        print('you are not login')
        return redirect(url_for('showTop'))
    else:
        print('you are logged in')
    if request.method == 'POST':
    # delete the category
        #check if the deleting category is being used.
        category = session.query(Category.id).filter(
            Category.category_name == request.form[
            'delete_category_name']).first()
        items = session.query(
            Items).filter(Items.category_id == category.id).all()
        cg_names = session.query(Category.category_name).all()
        if items:
            error_msg = 'The category name "{}" you want to delete \n \
                is being used. So you cannot delete this category. \n \
                Please edit or delete all items belong to the category. \n \
                '.format(request.form['delete_category_name'])
            print(error_msg)
            category = session.query(Category.category_name).all()
            return render_template(
                'bef_delete_category.html',
                error_msg = error_msg,
                cg_names = cg_names)
        else:
        #if the deleting category is not being used.
            session.query(Category).filter(
                Category.category_name == request.form[
                'delete_category_name']).delete()
            cg_names = session.query(
                Category).order_by(Category.category_name).all()
            return render_template(
                'aft_delete_category.html',
                cg_names = cg_names,
                deleted_cg = request.form['delete_category_name'])
    else:
    # if request.method == 'GET'
        category = session.query(Category.category_name).all()
        return render_template(
            'bef_delete_category.html',
            cg_names = category)



@app.route('/category/<string:category>/edit', methods=['GET', 'POST'])
def editCategory(category):
# change category name
    if 'username' not in login_session:
        print('you are not login')
        return redirect(url_for('showTop'))
    else:
        print('you are logged in')
        entered_category_name = category
    if request.method == 'POST':
        print('request accepted')
        # check the entered category name does exist
        categoryNew = session.query(
            Category).filter(
            Category.category_name == request.form['new_category_name']).first()
        if categoryNew:
        # if the entered category name does exist,
            if entered_category_name == request.form['new_category_name']:
            # if the entered category name is the same as it is.
                category = sesion.query(
                    Category.category_name).order_by(
                    Category.category_name).all()
                return render_template(
                    'edit_category.html',
                    category = category,
                    category_name = entered_category_name)
            else:
            # delete old category name
            # change all category id which goes with ald one
                categoryOld = session.query(
                    Category).filter(
                    Category.category_name == entered_category_name).first()
                # 変更前のカテゴリ名に該当する、カテゴリインスタンス作成
                items = session.query(Items).filter(
                    Items.category_id == categoryOld.id).all()
                print(type(items))
                print(items)
                print('#######################################################')
                items[0].category_id = categoryNew.id
                print(items[0].category_id)
                session.commit()
                # replacing category id by new one in Items table
                session.query(
                    Category).filter(
                    Category.id == categoryOld.id).delete()
                # delete old categry id in Category table
                categoryList = session.query(Category.category_name).all()
                return render_template(
                    'editedCategory.html',
                    category = categoryList,
                    old = entered_category_name,
                    new = request.form['new_category_name'],
                    items = items)
        else:
        # if the entered category name is new,
            category = session.query(
                Category).filter(
                Category.category_name == entered_category_name).all()
            print(entered_category_name)
            print(request.form['new_category_name'])
            print(type(category))
            print(category)
            category[0].category_name = request.form['new_category_name']
            session.commit()
            categoryList = session.query(Category.category_name).all()
            print(type(categoryList))
            print(categoryList)
            categoryID = session.query(
                Category.id).filter(
                Category.category_name == request.form[
                'new_category_name']).one()
            print(categoryID)
            print(type(categoryID))
            items = session.query(
                Items.item_name).filter(
                Items.category_id == categoryID.id).all()
            print('###########################################################')
            print(items)
            print(type(items))
            return render_template(
                'editedCategory.html',
                category = categoryList,
                old = entered_category_name,
                new = request.form['new_category_name'],
                items = items)
    if request.method == 'GET':
        category = session.query(Category).order_by(
            asc(Category.category_name)).all()
        if category == []:
            category = str("No such a category is registered yet.")
            print(category)
        return render_template(
            'edit_category.html',
            category = category,
            category_name = entered_category_name)



# Create a new items
# required login
@app.route('/item/new', methods=['GET', 'POST'])
def newItem():
    if 'username' not in login_session:
        print('you are not login')
        return redirect(url_for('showTop'))
    else:
        print('you are logged in')
    if request.method == 'POST':
        category_name = request.form['category']
        item_name = request.form['item_name']
        description = request.form['description']
        category = session.query(Category.id).filter(
            Category.category_name == category_name).first()
        newItem = Items(item_name=item_name, registered_at=str(
            datetime.now()), category_id=category.id, description=description)
        print(newItem)
        session.add(newItem)
        flash('New Item {} Successfully Created'.format(newItem.item_name))
        session.commit()
        return redirect(url_for('showTop'))
    else:
        category_names = session.query(Category.category_name).order_by(
            asc(Category.category_name)).all()
        if category_names == []:
            category_names = str("No category is registered yet.")
            print(category_names)
        return render_template('reg_item.html', category_names=category_names)


# Edit a item
# login in required
# String isn't correct, string is the right expression.
@app.route('/catalog/<string:item>/edit', methods=['GET', 'POST'])
def editedItem(item):
    if 'username' not in login_session:
        print('you are not login')
        return redirect(url_for('showTop'))
    else:
        print('you are logged in')
    print("item = {}".format(item))
    editedItem = session.query(Items.item_name, Items.description,
                               Items.category_id, Items.id).filter(
                               Items.item_name == item).first()
    if editedItem == None:
        print("NO such an item is registered")
    else:
        category_id = editedItem.category_id
        category_name = session.query(Category.category_name).filter(
            Category.id == category_id).first()
        category_list = session.query(Category.category_name).all()
        if request.method == 'POST':
            print("POST")
            # if request.form['item_name'] & request.form['description']:
            if request.form['item_name']:
                item_name = request.form['item_name']
                description = request.form['description']
                category_name = request.form['category_name']
                item_id = request.form['item_id']
                # check item_id's item_name is the same as entered or not.
                items = session.query(Items.item_name).filter(
                    Items.item_name == item_name).first()
                if items == None:
                    items = session.query(Items).filter(
                        Items.id == item_id).one()
                    items.item_name = item_name
                    items.registered_at = str(datetime.now())
                    session.add(items)
                    session.commit()
                else:
                    items = session.query(Items.description).filter(
                        Items.description == description).first()
                if items == None:
                    items = session.query(Items).filter(
                        Items.id == item_id).one()
                    items.description = description
                    items.registered_at = str(datetime.now())
                    session.add(items)
                    session.commit()

                category = session.query(Category.id).filter(
                    Category.category_name == category_name).one()
                items = session.query(Items).filter(Items.id == item_id).one()
                if category.id != items.category_id:
                    items.category_id = category.id
                    items.registered_at = str(datetime.now())
                    session.add(items)
                    session.commit()
                else:
                    flash('New Item Successfully Edited {}'.format(item_name))
                return redirect(url_for('showTop'))
        else:
            print('$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$')
            return render_template(
                'edit_item.html', editedItem=editedItem,
                category=category_name, category_list=category_list)


# Delete an item.
# login is required
@app.route('/catalog/<string:item>/delete', methods=['GET', 'POST'])
def deleteItem(item):
    if 'username' not in login_session:
        print('you are not login')
        return redirect(url_for('showTop'))
    else:
        print('you are login')
    itemsToDelete = session.query(Items).filter(Items.item_name == item).one()
    if request.method == 'POST':
        session.delete(itemsToDelete)
        session.commit()
        return redirect(url_for('showTop'))
    else:
        return render_template('deleteItem.html', items=itemsToDelete)


# Show an items detail.
@app.route('/catalog/<string:category>/<string:item>')
def showItem(category, item):
    category = session.query(Category).filter(
        Category.category_name == category).one()
    items = session.query(Items).filter(Items.item_name == item).one()
    if 'username' not in login_session:
        print('you are not login')
        return render_template('showItem.html', items=items, category=category)
    else:
        print('you are login')
        return render_template(
            'showItemLogin.html', items=items, category=category)


# authorization processes
CLIENT_ID = json.loads(
    open('/home/grader/catalog/catalog/client_secrets.json', 'r').read())['web']['client_id']
print(CLIENT_ID)


@auth.verify_password
def verify_password(username_or_token, password):
    # Try to see if it's a token first
    user_id = User.verify_auth_token(username_or_token)
    if user_id:
        user = session.query(User).filter_by(id=user_id).one()
    else:
        user = session.query(User).filter_by(
            username=username_or_token).first()
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route('/clientOAuth')
def start():
    return render_template('clientOAuth.html')


@app.route('/oauth/<provider>', methods=['POST'])
def login(provider):
    # STEP 1 - Parse the auth code
    auth_code = request.get_data()
    if provider == 'google':
        # STEP 2 - Exchange for a token
        try:
            # Upgrade the authorization code into a credentials object
            oauth_flow = flow_from_clientsecrets(
                '/home/grader/catalog/catalog/client_secrets.json', scope='')
            oauth_flow.redirect_uri = 'postmessage'
            credentials = oauth_flow.step2_exchange(auth_code)
        except FlowExchangeError:
            response = make_response(json.dumps(
                'Failed to upgrade the authorization code.'), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # Check that the access token is valid.
        access_token = credentials.access_token
        url = (
            'https://www.googleapis.com/oauth2/v1/tokeninfo?access_token={}'.
            format(access_token))
        h = httplib2.Http()
        result = json.loads(h.request(url, 'GET')[1].decode("utf-8"))
        print("access token is verified")
        # If there was an error in the access token info, abort.
        if result.get('error') is not None:
            response = make_response(json.dumps(result.get('error')), 500)
            response.headers['Content-Type'] = 'application/json'

        # Verify that the access token is used for the intended user.
        gplus_id = credentials.id_token['sub']
        if result['user_id'] != gplus_id:
            response = make_response(json.dumps(
                "Token's user ID doesn't match given user ID."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        # # Verify that the access token is valid for this app.
        if result['issued_to'] != CLIENT_ID:
            response = make_response(json.dumps(
                "Token's client ID does not match app's."), 401)
            response.headers['Content-Type'] = 'application/json'
            return response

        stored_credentials = login_session.get('credentials')
        stored_gplus_id = login_session.get('gplus_id')
        if stored_credentials is not None and gplus_id == stored_gplus_id:
            response = make_response(json.dumps(
                'Current user is already connected.'), 200)
            response.headers['Content-Type'] = 'application/json'
            return response
        print("Step 2 Complete! Access Token : {}".format(
            credentials.access_token))

        # Get user info
        h = httplib2.Http()
        userinfo_url = "https://www.googleapis.com/oauth2/v1/userinfo"
        params = {'access_token': credentials.access_token, 'alt': 'json'}
        answer = requests.get(userinfo_url, params=params)
        data = answer.json()
        name = data['name']
        picture = data['picture']
        email = data['email']

        # copied 112-114 from
        # https://github.com/udacity/ud330/blob/master/Lesson3/step3/project.py
        login_session['username'] = data['name']
        login_session['picture'] = data['picture']
        login_session['email'] = data['email']
        login_session['gplus_id'] = data['id']
        login_session['access_token'] = credentials.access_token
        # see if user exists, if it doesn't make a new one
        user = session.query(User).filter_by(email=email).first()
        if not user:
            print("Since no data in UserDB, add the user info into the DB")
            user = User(username=name, picture=picture, email=email)
            session.add(user)
            session.commit()

        # STEP 4 - Make token
        token = user.generate_auth_token(600)

        # STEP 5 - Send back token to the client
        return jsonify({'token': token.decode('ascii')})
        # return jsonify({'token': token.decode('ascii'), 'duration': 600})
    else:
        return 'Unrecoginized Provider'


@app.route('/gdisconnect')
def gdisconnect():
    # Only disconnect a connected user.
    print("starts gdisconnect")
    access_token = login_session.get('access_token')
    print(access_token)
    print(type(access_token))
    if access_token is None:
        response = make_response(
            json.dumps('Current user not connected.'), 401)
        response.headers['Content-Type'] = 'application/json'
        return response
    url = (
        'https://accounts.google.com/o/oauth2/revoke?token={}'
        .format(access_token))
    print("url = {}".format(url))
    h = httplib2.Http()
    result = h.request(url, 'GET')[0]
    print(result)
    print(type(result))
    if result['status'] == '200':
        print("200")
        # Reset the user's sesson.
        del login_session['access_token']
        del login_session['gplus_id']
        del login_session['username']
        del login_session['email']
        del login_session['picture']
        response = make_response(json.dumps('Successfully disconnected.'), 200)
        response.headers['Content-Type'] = 'application/json'
        print(response)
        print(type(response))
        # return response
        return render_template('logout.html', response=response)
    else:
        print("not 200")
        # For whatever reason, the given token was invalid.
        response = make_response(
            json.dumps('Failed to revoke token for given user.', 400))
        response.headers['Content-Type'] = 'application/json'
        return response


@app.route('/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token()
    return jsonify({'token': token.decode('ascii')})


@app.route('/users', methods=['POST'])
def new_user():
    username = request.json.get('username')
    password = request.json.get('password')
    if username is None or password is None:
        print("missing arguments")
        abort(400)

    if session.query(User).filter_by(username=username).first() is not None:
        print("existing user")
        user = session.query(User).filter_by(username=username).first()
        return jsonify({'message': 'user already exists'}), 200

    user = User(username=username)
    user.hash_password(password)
    session.add(user)
    session.commit()
    return jsonify({'username': user.username}), 201


if __name__ == '__main__':
    app.secret_key = 'super_secret_key'
    app.debug = True
    app.run(host='0.0.0.0', port=80)
