from flask import Flask, render_template, url_for, redirect,request,session
from flask_sqlalchemy import SQLAlchemy
from flask_login import UserMixin, login_user, LoginManager, login_required, logout_user, current_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField,validators,TimeField
from wtforms.validators import InputRequired, Length, ValidationError
from flask_bcrypt import Bcrypt
from wtforms.fields import DateField,DateTimeField
app = Flask(__name__)
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SECRET_KEY'] = 'thisisasecretkey'


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), nullable=False, unique=True)
    password = db.Column(db.String(80), nullable=False)
    admin=db.Column(db.BOOLEAN(create_constraint=False), default=False)

class Medici(db.Model, UserMixin):
    id_m= db.Column(db.Integer, primary_key=True, unique=True)
    nume_m = db.Column(db.String(20), nullable=False, unique=True)
    prenume_m = db.Column(db.String(20), nullable=False)
    varsta_m = db.Column(db.Integer, nullable=False)
    spital_m = db.Column(db.String(20), nullable=False)
    specializare_m = db.Column(db.String(20), nullable=False)
    mail_m = db.Column(db.String(20),nullable=False, unique=True)
    telefon_m = db.Column(db.String(11), nullable=False)


class Pacienti(db.Model, UserMixin):
    id_p = db.Column(db.Integer, primary_key=True, unique=True)
    nume_p = db.Column(db.String(20), nullable=False, unique=True)
    prenume_p = db.Column(db.String(20), nullable=False)
    varsta_p = db.Column(db.Integer, nullable=False)
    mail_p = db.Column(db.String(20),nullable=False, unique=True)
    telefon_p = db.Column(db.String(11), nullable=False)
    conditie_p = db.Column(db.String(20), nullable=False)

class Programari(db.Model, UserMixin):
    id_prog = db.Column(db.Integer, primary_key=True, unique=True)
    id_p = db.Column(db.Integer, unique=True)
    data_prog = db.Column(db.String(20),nullable=False, unique=False, index=False)
    ora_prog = db.Column(db.String(20)) 
    id_m = db.Column(db.Integer, unique=True)

class Medicamente(db.Model, UserMixin):
    id_med =  db.Column(db.Integer, primary_key=True, unique=True)
    nume_med = db.Column(db.String(20), nullable=False)
    firma_med = db.Column(db.String(20), nullable=False)
    cant_med = db.Column(db.Integer, nullable=False)
    ingr_activ= db.Column(db.Integer, nullable=False)

db.drop_all()
pacient1 = Pacienti(id_p=3,nume_p='Mihnea',prenume_p='Mihnea',varsta_p=30,mail_p='ceva',telefon_p="1111@gmail.com",conditie_p='123456')
medic = Medici(nume_m="Costel",prenume_m ="Costel1",varsta_m=30,spital_m ="Mama urs",specializare_m="Departament 1",mail_m="fsd30",telefon_m="34")
medicament= Medicamente(nume_med="Nurofen",firma_med ="Firma 1",cant_med =10,ingr_activ=1000)
programare1 = Programari(id_p=4324,data_prog='17-01-23',ora_prog='23:10',id_m=3213)
db.session.add(medic)
db.session.add(pacient1)
db.session.add(medicament)
db.session.add(programare1)
db.create_all()
db.session.commit()


class RegisterForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Register')

    def validate_username(self, username):
        existing_user_username = User.query.filter_by(
            username=username.data).first()
        if existing_user_username:
            raise ValidationError(
                'That username already exists. Please choose a different one.')


class LoginForm(FlaskForm):
    username = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Username"})

    password = PasswordField(validators=[
                             InputRequired(), Length(min=8, max=20)], render_kw={"placeholder": "Password"})

    submit = SubmitField('Login')


class InfoForm(FlaskForm):
    startdate = DateField('Date', format='%Y-%m-%d', validators=(validators.DataRequired(),))
    idPacient= StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "ID pacient"})
    time = TimeField('Time', format='%H:%M')
    submit = SubmitField('Submit')



class CautarePacienti(FlaskForm):
    numePacientCautare = StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Nume pacient"})    
    prenumePacientCautare=StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Prenume pacient"})    
    submit = SubmitField('Submit')


class CautareProgramari(FlaskForm):
    timeCautare = TimeField('Time', format='%H:%M')
    dateCautare = DateField('Date', format='%Y-%m-%d', validators=(validators.DataRequired(),)) 
    submit = SubmitField('Submit')

class CautareMedicament(FlaskForm):
    ingredientActivCautare= StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Ingredient activ"})  
    submit = SubmitField('Submit')

class CautareMedici(FlaskForm):
    prenumeMedicCautare=StringField(validators=[
                           InputRequired(), Length(min=4, max=20)], render_kw={"placeholder": "Prenume medic"})  
    submit = SubmitField('Submit')

@app.route('/', methods=['GET', 'POST'])
def home():
    return redirect(url_for('register'))


@app.route('/index', methods=['GET', 'POST'])
@login_required
def index():
    if request.method == 'POST':
        session['departament']=request.form.get('comp_select2') 
        if(session.get('departament')!=""):
            return redirect(url_for('tabelDepartament'))

    form = InfoForm()
    if form.validate_on_submit():

        session['startdate'] = form.startdate.data.strftime('%d-%m-%y')
        session['nume']=request.form.get('comp_select')
        session['idPacient']=form.idPacient.data
        session['time']=str(form.time.data.hour )+":"+str(form.time.data.minute)

        programare = Programari(id_p=session.get('idPacient'),data_prog =session.get('startdate'),ora_prog =session.get('time'),id_m =session.get('nume'))
        db.session.add(programare)
        db.create_all()
        db.session.commit()
    
    return render_template('index.html',data1=[{'name':'Departament 1'}, {'name':'Departament 2'}, {'name':'Departament 3'}] ,data=[{'name':'Selecteaza medic'},{'name':'Medic 1'}, {'name':'Medic 2'}, {'name':'Medic 3'}],form=form )


@app.route('/medici', methods=['GET', 'POST'])
@login_required
def medici():
    form = CautareMedici()
    if form.validate_on_submit():
        session['departamentCautare']=request.form.get('comp_select3')
        session['prenumeMedicCautare']=form.prenumeMedicCautare.data
        #return  str( session.get('departamentCautare')) +" "+str(session.get('prenumeMedicCautare'))
        return redirect(url_for('tabelMedic'))
    return render_template('medici.html',  data=[{'name':'Departament'},{'name':'Departament 1'}, {'name':'Departament 2'}, {'name':'Departament 3'}],form=form )

@app.route('/tabelMedic', methods=['GET', 'POST'])
@login_required
def tabelMedic():
    medici = Medici.query.filter_by(specializare_m =session.get('departamentCautare'),prenume_m =session.get('prenumeMedicCautare'))
    return render_template('tabelMedic.html', medici=medici)


@app.route('/tabelDepartament', methods=['GET', 'POST'])
@login_required
def tabelDepartament():
    medici = Medici.query.filter_by(specializare_m =session.get('departament'))
    session['departament']=""
    return render_template('tabelMedic.html', medici=medici)


@app.route("/test" , methods=['GET', 'POST'])
def test():
    select = session.get('nume')
    select1= session.get('startdate')
    return(str(select) + str(select1)) # just to see what select is

@app.route('/medicamente', methods=['GET', 'POST'])
@login_required
def medicamente():
    form = CautareMedicament()
    if form.validate_on_submit():
        session['firmaCautare']=request.form.get('comp_select2')
        session['ingredientActivCautare']=form.ingredientActivCautare.data
        #return str(session.get('firmaCautare') + session.get('ingredientActivCautare')) 
        return redirect(url_for('tabelMedicamente'))

    return render_template('medicamente.html',  data=[{'name':'Firma'},{'name':'Firma 1'}, {'name':'Firma 2'}, {'name':'Firma 3'}], form=form)


@app.route('/tabelMedicamente', methods=['GET', 'POST'])
@login_required
def tabelMedicamente():

    medicamente = Medicamente.query.filter_by(firma_med =session.get('firmaCautare'),ingr_activ=session.get('ingredientActivCautare'))
    return render_template('tabelMedicamente.html', medicamente=medicamente)


@app.route('/pacienti', methods=['GET', 'POST'])
@login_required
def pacienti():
    form = CautarePacienti()
    if form.validate_on_submit():
        session['numePacientCautare']=form.numePacientCautare.data
        session['prenumePacientCautare']=form.prenumePacientCautare.data
        return redirect(url_for('tabelPacienti'))
        
    #str( session.get('numePacientCautare')) +" "+str(session.get('prenumePacientCautare'))
    return render_template('pacienti.html', form=form)

@app.route('/tabelPacienti', methods=['GET', 'POST'])
@login_required
def tabelPacienti():
    pacienti = Pacienti.query.filter_by(nume_p=session.get('numePacientCautare'),prenume_p=session.get('prenumePacientCautare'))
    return render_template('tabelPacienti.html', pacienti=pacienti)



@app.route('/programari', methods=['GET', 'POST'])
@login_required
def programari():
    form = CautareProgramari()
    if form.validate_on_submit():
        session['dateCautare'] = form.dateCautare.data.strftime('%d-%m-%y')
        session['timeCautare']=str(form.timeCautare.data.hour )+":"+str(form.timeCautare.data.minute) 
        return redirect(url_for('tabelProgramari'))
    return render_template('programari.html',form=form)


@app.route('/tabelProgramari', methods=['GET', 'POST'])
@login_required
def tabelProgramari():
   # return str(session.get('dateCautare'))
    programari = Programari.query.filter_by(data_prog=session.get('dateCautare'),ora_prog=session.get('timeCautare'))
    return render_template('tabelProgramari.html', programari=programari)




@app.route('/appointment', methods=['GET', 'POST'])
@login_required
def appointment():
    form = InfoForm()
    if form.validate_on_submit():
        session['startdate'] = form.startdate.data.strftime('%d-%m-%y')
        session['nume']=request.form.get('comp_select')
        session['idPacient']=form.idPacient.data
        session['time']=str(form.time.data.hour )+":"+str(form.time.data.minute)
        programare = Programari(id_p=session.get('idPacient'),data_prog =session.get('startdate'),ora_prog =session.get('time'),id_m =session.get('nume'))
        db.session.add(programare)
        db.create_all()
        db.session.commit()
    return render_template('appointment.html',  data=[{'name':'Selecteaza medic'},{'name':'Medic 1'}, {'name':'Medic 2'}, {'name':'Medic 3'}],form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user:
            if bcrypt.check_password_hash(user.password, form.password.data):
                login_user(user)
                #if user.admin==True:
                #    return render_template('index.html', admin='admin', data=[{'name':'Selecteaza medic'},{'name':'Medic 1'}, {'name':'Medic 2'}, {'name':'Medic 3'}] )
                return redirect(url_for('index'))
                #return render_template('index.html', admin='user', data=[{'name':'Selecteaza medic'},{'name':'Medic 1'}, {'name':'Medic 2'}, {'name':'Medic 3'}] )
    return render_template('login.html', form=form)


@app.route('/dashboard', methods=['GET', 'POST'])
@login_required
def dashboard():
    if request.method == 'POST':
        if 'action1' in request.form:
            return render_template('dashboard.html',admin="admin")
        elif 'action2' in request.form:
            return render_template('dashboard.html',admin="admin")
        else:
            pass # unknown
    return render_template('dashboard.html')


@app.route('/logout', methods=['GET', 'POST'])
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))


@ app.route('/register', methods=['GET', 'POST'])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        hashed_password = bcrypt.generate_password_hash(form.password.data)
        if form.username.data=='contcontcont':
            new_user = User(username=form.username.data, password=hashed_password,admin=True)
        else:
            new_user = User(username=form.username.data, password=hashed_password,admin=False)
        db.session.add(new_user)
        db.session.commit()
        return redirect(url_for('login'))

    return render_template('register.html', form=form)


if __name__ == "__main__":
    app.run(debug=True)