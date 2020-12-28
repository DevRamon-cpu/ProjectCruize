<?php

namespace App\Http\Controllers\Admin;

use App\Http\Controllers\Controller;

use App\Mail\SendEmail;
use App\Models\User;
use App\Models\UserConfig;
use App\Models\UserTemp;
use Exception;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Mail;
use stdClass;
use Carbon\Carbon;

    /**
     * This file was created by Daniel X. Don't remove this credits.
     */
class cadastrar extends Controller
{
  
    protected $token, $user, $usertemp, $log,$pattern = '/[\'\/~`\!@#\$%\^&\*\(\)_\-\+=\{\}\[\]\|;:"\<\>,\.\?\\\]/';
    protected $recaptcha = true;
    protected $confirmar_token = true;
    protected $verificar_email = true;
    protected $min_user = 5;
    protected $max_user = 10;
    protected $min_pass = 5;
    protected $max_pass = 10;
    protected $list = 'safelist';
    protected $blacklist = array('outlook.com', 'teste.com', 'sla.com');
    protected $safelist = array('gmail.com','outlook.com');
    protected $blacklist_user = array('tmp', 't.m.p', 'cruize', 'elite', 'fireway', 'temporaria', 'teste');

    public function __construct()
    {
        if (Auth::check()) {
            return route('home');
        } else {
            $this->token = new Token;
            $this->user = new User();
            $this->usertemp = new UserTemp();
            $this->config = UserConfig::first();
        }
    }

    /**
     * Display the registration form
     *
     * 
     *
     * @return auth.cadastrar
     */
    public function ShowCadastro()
    {
        return view('auth.cadastrar');
    }

    /**
     * Transform a string into a client md5 hash
     *
     * 
     * @return string Hashed
     */
    public static function hashMd5($hash)
    {
        $salt = '/x!a@r-$r%an¨.&e&+f*f(f(a)';
        $output = hash_hmac('md5', $hash, $salt);
        return $output;
    }

    /**
     * Recaptcha check by cUrl
     *
     * 
     * @return bool
     */
    public static function recaptcha($captcha)
    {
        try {
            if (isset($captcha)) {
                $captcha_data = $captcha;
            }
            if (!$captcha_data) {
                return false;
            }

            $data = array(
                'secret' => "SECRET KEY",
                'response' => $captcha_data
            );

            $verify = curl_init();
            curl_setopt($verify, CURLOPT_URL, "https://www.google.com/recaptcha/api/siteverify");
            curl_setopt($verify, CURLOPT_POST, true);
            curl_setopt($verify, CURLOPT_POSTFIELDS, http_build_query($data));
            curl_setopt($verify, CURLOPT_SSL_VERIFYPEER, false);
            curl_setopt($verify, CURLOPT_RETURNTRANSFER, true);
            return curl_exec($verify);
        } catch (Exception $e) {
            return redirect()->back()->withInput()->withErrors(['Ocorreu um erro desconhecido. $1']);
            die();
        }
    }

    /**
     * Get the token and enter it into accounts if this token is true
     *
     * 
     * @return string
     */
    public function ReceivedToken($id, $token)
    {
        $current_timestamp = Carbon::now()->timestamp;
        $count_temp = UserTemp::where('hash', $token)->where('id', $id)->count();
        if ($count_temp > 0) {

            $UserTemp = UserTemp::where('hash', $token)->where('id', $id)->first();



            try {

                $data =   [
                    'login' => strtolower($UserTemp->usuario),
                    'password' =>  $UserTemp->password,
                    'create_data' => $current_timestamp,
                    'email' =>  $UserTemp->mail,
                    'gp' => (int)$this->config->gold,
                    'money' => (int)$this->config->cash,
                    'remember_token' => null
                ];
                $created = $this->db::create($data);
                if ($created) {
                    UserTemp::where('hash', $token)->where('id', $id)->delete();
                    $user = User::where('login', $UserTemp->usuario)->where('password', $UserTemp->password)->first();
                    Auth::loginUsingId($user->id, TRUE);
                    if (Auth::check()) {
                        return redirect()->route('home');
                    } else {
                        return redirect()->back()->withInput()->withErrors(['Os dados informados não conferem']);
                    }
                } else {
                    return redirect()->back()->withInput()->withErrors(['Não foi possivel criar sua conta, contate o suporte.']);
                }
            } catch (Exception $e) {
                return redirect()->back()->withInput()->withErrors(['Ocorreu um erro ao tentar cadastrar a conta, contate o suporte.']);
            }
        }
        return redirect()->back()->withInput()->withErrors(['O token está incorreto.']);
    }

    /**
     * Checks Recaptcha
     *
     * 
     * @return string
     */
    private function Verify_Recaptcha()
    {
        if ($this->recaptcha) {
            $recaptcha = cadastrar::recaptcha($_POST['g-recaptcha-response']);
            if (!$recaptcha) {
                return redirect()->back()->withInput()->withErrors(['O Recaptcha está incorreto.']);
            }
        }
    }

    /**
     * Verify Email if is true, if no return error string
     *
     * Switchs - cases 
     * @safelist 
     * @blacklist 
     * 
     * @return string
     */
    private function Verify_Email($email)
    {
        if($this->verificar_email){
            $exploded = explode("@", $email);
            switch ($this->list) {
                case "safelist": {
                        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                            if ($this->confirmar_token) {
                                return redirect()->back()->withInput()->withErrors(['Insira um email valido, pois enviaremos uma confirmação para continuar seu cadastro.']);
                            } else {
                                return redirect()->back()->withInput()->withErrors(['Insira um email valido.']);
                            }
                        }
    
                        $counter = 0;
                        foreach ($this->blacklist as $blacklist) {
                            if (strpos(strtolower($exploded[0]), $blacklist)) {
                                return redirect()->back()->withInput()->withErrors(
                                    ['A utilização de ' . $blacklist . ' não é permitida.']
                                );
                            }
                        }
                        foreach ($this->safelist as $safelist) {
                            if (strtolower($exploded[1]) == $safelist) {
                                $counter++;
                            }
                        }
                        if ($counter == 0) {
                            return redirect()->back()->withInput()->withErrors(
                                ['A utilização de ' . $exploded[1] . ' não é permitida.']
                            );
                        }
                        break;
                    }
                case "blacklist": {
                        if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                            if ($this->confirmar_token) {
                                return redirect()->back()->withInput()->withErrors(['Insira um email valido, pois enviaremos uma confirmação para continuar seu cadastro.']);
                            } else {
                                return redirect()->back()->withInput()->withErrors(['Insira um email valido.']);
                            }
                        }
                        foreach ($this->blacklist as $blacklist) {
                            if (strpos(strtolower($exploded[0]), $blacklist)) {
                                return redirect()->back()->withInput()->withErrors(
                                    ['A utilização de ' . $blacklist . ' não é permitida.']
                                );
                            }
                        }
                        break;
                    }
                default:
                    return redirect()->back()->withInput()->withErrors(
                        ['Utilização de uma listagem incorreta.']
                    );
            }
        }else{
            if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
                if ($this->confirmar_token) {
                    return redirect()->back()->withInput()->withErrors(['Insira um email valido, pois enviaremos uma confirmação para continuar seu cadastro.']);
                } else {
                    return redirect()->back()->withInput()->withErrors(['Insira um email valido.']);
                }
            }
        }
    }

    /**
     * Verify user if is true, if no return error string
     *
     * checks - cases 
     * @space 
     * @number
     * @Character Special
     * @min Lenght
     * @max Lenght 
     * 
     * @return string
     */
    private function Verify_Usuario($user)
    {

        //check to see if there are any words on the blacklist
        foreach ($this->blacklist_user as $blacklist_user) {
            if (strpos(strtolower($user), $blacklist_user)) {
                return redirect()->back()->withInput()->withErrors(
                    ['A utilização de ' . $blacklist_user . ' não é permitida no usuario.']
                );
            }
        }

        //check if user contains space
        if (preg_replace('/(.*?)[\n\t\s].*/', '\1', $user) != $user) {
            return redirect()->back()->withInput()->withErrors(['O usuario não pode possuir espaços.']);
        }

        $check_user = $this->user::where('login', $user)->count();
        $check_usertemp = $this->usertemp::where('usuario', $user)->count();
        //check if user was exists
        if ($check_user > 0 || $check_usertemp > 0) {
            return redirect()->back()->withInput()->withErrors(['Já existe um usuario com este nome.']);
        }

        //check if user is numeric
        if (is_numeric($user)) {
            return redirect()->back()->withInput()->withErrors(['O usuario não pode começar com numeros.']);
        }

        //check if user contains one or more characters special
        if (preg_match($this->pattern, $user)) {
            return redirect()->back()->withInput()->withErrors(['O usuario não pode conter caracteres especiais.']);
        }

        //check if user contains min lenght of characters
        if (strlen($user) < $this->min_user) {
            return redirect()->back()->withInput()->withErrors(['O usuario precisa conter mais do que ' . $this->min_user . ' palavras.']);
        }
        //make sure the user contains more length than the maximum character length
        if (strlen($user) > $this->max_user) {
            return redirect()->back()->withInput()->withErrors(['O usuario precisa conter menos que ' . $this->max_user . ' palavras.']);
        }
    }

    /**
     * Verify password and subsequent checks
     *
     * checks - cases 
     * @space 
     * @min Lenght
     * @max Lenght 
     * 
     * @return string Hashed
     */
    private function Verify_Password($pass, $pass_2)
    {
        if (preg_replace('/(.*?)[\n\t\s].*/', '\1', $pass) != $pass) {
            return redirect()->back()->withInput()->withErrors(['A senha não pode possuir espaços.']);
        }
        if (preg_replace('/(.*?)[\n\t\s].*/', '\1', $pass_2) != $pass_2) {
            return redirect()->back()->withInput()->withErrors(['A senha não pode possuir espaços.']);
        }
        if (strlen($pass) < $this->min_pass) {
            return redirect()->back()->withInput()->withErrors(['As senhas precisam conter mais do que ' . $this->min_pass . ' digitos.']);
        }
        if (strlen($pass) > $this->max_pass) {
            return redirect()->back()->withInput()->withErrors(['As senhas precisam conter menos do que ' . $this->max_pass . ' digitos.']);
        }
        if ($pass != $pass_2) {
            return redirect()->back()->withInput()->withErrors(['As senhas não conferem.']);
        }

        $md5 = cadastrar::hashMd5($pass);
        return $md5;
    }


    /**
     * Verification of terms of use
     *
     * @return string Error
     */
    private function Verify_Termos($termos)
    {
        if ($termos != "on") {
            return redirect()->back()->withInput()->withErrors(['Você precisa concordar com os termos de uso.']);
        }
    }

    /**
     * Create a new user in accounts or Temporary Accounts
     *
     * @return bool 
     */
    private function NewUser(array $data)
    {
        if ($this->confirmar_token) {
            $created = $this->db::create($data);
            if ($created) {
                $user = User::where('login', $data['login'])->where('password', $data['password'])->first();
                Auth::loginUsingId($user->id, TRUE);
                if (Auth::check()) {
                    return true;
                }
            }
            return false;
        } else {
            $usuario =  UserTemp::create($data);
            if ($usuario) {
                $id = UserTemp::select('id', 'hash')->where('usuario', strtolower($data['login']))->first();
                $userMail = new stdClass();
                $userMail->name = strtolower($data['login']);
                $userMail->email = $data['email'];
                $userMail->token = $id->hash;
                $userMail->player_id = $id->id;
                Mail::send(new SendEmail($userMail));
                return true;
            }
            return false;
        }
    }

    /**
     * User registration and subsequent checks.
     *
     * @return string
     */
    public function Cadastrar(Request $request)
    {


        $token = $this->token->GetToken();

        //Verificação de Usuario
        $this->Verify_Usuario($request->usuario);

        //Verificação de Email
        $this->Verify_Email($request->email);

        //Verificação de Senha
        $md5 = $this->Verify_Password($request->senha, $request->password_confirm);

        //Verificação de Recaptcha
        $this->Verify_Recaptcha();

        //Verificação de Termos de uso
        $this->Verify_Termos($request->termos_de_uso);


        $current_timestamp = Carbon::now()->timestamp;

        if ($this->confirmar_token) {
            $data =   [
                'login' => strtolower($request->usuario),
                'password' => $md5,
                'create_data' => $current_timestamp,
                'email' => $request->email,
                'gp' => (int)$this->config->gold,
                'money' => (int)$this->config->cash,
                'remember_token' => null
            ];
            $created = $this->NewUser($data);
            if ($created) {
                return redirect()->route('home');
            }
            return redirect()->back()->withInput()->withErrors(['Os dados informados não conferem']);
        } else {
            $data =   [
                'login' => strtolower($request->usuario),
                'password' => $md5,
                'email' => $request->email,
                'hash' => $token,
            ];
            $created = $this->NewUser($data);
            if ($created) {
                $request->session()->flash('alert-success', "Um e-mail para o cadastro foi enviado com sucesso.");
                return redirect()->route('login');
            }
            return redirect()->back()->withInput()->withErrors(['ocorreu um erro inesperado']);
        }
    }

    /**
     * Confirm key if true and add new user .
     *
     * @return string
     */
    public function ConfirmarToken(Request $request)
    {

        $count_user = UserTemp::where('hash', $request->hash)->where('usuario', $request->usuario)->count();
        if ($count_user > 0) {
            $UserTemp = UserTemp::where('hash', $request->hash)->where('usuario', $request->usuario)->first();
         
            $current_timestamp = Carbon::now()->timestamp;
            $data =   [
                'login' => strtolower($UserTemp->usuario),
                'password' => $UserTemp->password,
                'create_data' => $current_timestamp,
                'email' => $UserTemp->mail,
                'gp' => (int)$this->config->gold,
                'money' => (int)$this->config->cash,
                'remember_token' => null ];
            $created =  $this->db::create($data);
            if ($created) {
                UserTemp::where('hash', $request->hash)->where('usuario', $UserTemp->usuario)->delete();
                $user = User::where('login', $UserTemp->usuario)->where('password', $UserTemp->password)->first();
                Auth::loginUsingId($user->id, TRUE);
                if (Auth::check()) {
                    return redirect()->route('home');
                } else {
                    return redirect()->back()->withInput()->withErrors(['Os dados informados não conferem']);
                }
            }
            return redirect()->back()->withInput()->withErrors(['Os dados informados não conferem']);
        }
        return redirect()->back()->withInput()->withErrors(['O token está incorreto.']);
    }
}
?>
