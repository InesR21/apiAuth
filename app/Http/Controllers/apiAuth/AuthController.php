<?php

namespace App\Http\Controllers\apiAuth;

use App\Http\Controllers\Controller;
use Illuminate\Http\Request;
//
use App\User; 
use Illuminate\Support\Facades\Auth; 
use Validator;
use stdClass;


/**
* @OA\Info(title="API Auth", version="1.0")
*
* @OA\Server(url="http://127.0.0.1:8000/")
*/

class AuthController extends Controller
{
    public $successStatus = 200;
/** 
* login api 
* 
* @return \Illuminate\Http\Response 
*/ 


/**
 * @OA\Post(
 *     path="/api/login",
 *     description="login",
 *     @OA\Parameter(
 *         name="email",
 *         in="query",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),
 *      @OA\Parameter(
 *         name="password",
 *         in="query",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="success and Token",
 *     ),
 * )
 */
public function login() { 
    if( Auth::attempt( ['email' => request('email'), 'password' => request('password')] ) ) { 
        $user = Auth::user(); 
        $success['token'] =  $user->createToken('MyApp')-> accessToken; 
        return response()->json(['success' => $success], $this-> successStatus); 
    } else{ 
        return response()->json(['error'=>'Unauthorised'], 401); 
    } 
}
/** 
* Register api 
* 
* @return \Illuminate\Http\Response 
*/ 


/**
 * @OA\Post(
 *     path="/api/register",
 *     description="register",
 *     @OA\Parameter(
 *         name="name",
 *         in="query",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),
 *      @OA\Parameter(
 *         name="email",
 *         in="query",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),
 *  *      @OA\Parameter(
 *         name="password",
 *         in="query",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),
 *  *      @OA\Parameter(
 *         name="c_password",
 *         in="query",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),
 *     @OA\Response(
 *         response=200,
 *         description="success and Token",
 *     ),
 * )
 */

public function register(Request $request) { 
    $validator = Validator::make($request->all(), [ 
        'name' => 'required', 
        'email' => 'required|email', 
        'password' => 'required', 
        'c_password' => 'required|same:password', 
    ]);
    if ($validator->fails()) { 
        return response()->json(['error'=>$validator->errors()], 401);            
    }
    $input = $request->all(); 
    $input['password'] = bcrypt($input['password']); 
    $user = User::create($input); 
    $success['token'] =  $user->createToken('MyApp')-> accessToken; 
    $success['name'] =  $user->name;
    return response()->json(['success'=>$success], $this-> successStatus); 
}
/** 
* emailValidation api 
* 
* @return \Illuminate\Http\Response 
*/ 

/**
 * @OA\Get(
 *     path="/api/emailValidation/{email}",
 *     description="validate an email",
 *     @OA\Parameter(
 *         name="email",
 *         in="path",
 *         description=" validate an email",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ), @OA\Parameter(
 *         name="Accept",
 *         in="header",
 *         required=false,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),  @OA\Parameter(
 *         name="Authorization",
 *         in="header",
 *         required=true,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ),  @OA\Parameter(
 *         name="Content-Type",
 *         in="header",
 *         required=false,
 *         @OA\Schema(
 *              type="string"
 *          )
 *     ), 
 *     @OA\Response(
 *         response=200,
 *         description="return a JSON with true if it is a valid email, or false if it is not",
 *     ),
 * )
 */

public function emailValidation($email) 
    { 
        $std = new stdClass();
        $std->valid = false;
        $std->email = $email;
        $result = false;
        // valido con la función filter_var
        if ( false !== filter_var($email, FILTER_VALIDATE_EMAIL) ) {
                $result = true;
            }
        // valido que tenga un registro MX
        if ($result) {
            list($user, $domain) = explode('@', $email);
            $result = checkdnsrr($domain, 'MX');
        }
        if ($result) {
            $std->valid = true;
        }
        $jsonresponse = json_encode($std);
        return $jsonresponse;
    } 

}
