<?php

namespace App\Http\Controllers;

use App\User;
use Carbon\Carbon;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Validator;


class AuthController extends Controller
{
    //CREATE USER AND GENERATE TOKEN.
    public function register(Request $request)
    {
        //Check Validation
        $validator = Validator::make($request->all(), [
            'name' => 'required|string|max:225',
            'email' => 'required|string|max:225|unique:users',
            'password' => 'required|string|max:225|min:6',
        ]);

        if ($validator->fails()) {
            return response(['errors' => $validator->errors()], 422);
        }

        //Save the User
        $user = new User();
        $user->name = $request->name;
        $user->email = $request->email;
        $user->password = bcrypt($request->password);
        $user->save();

        return $this->getResponse($user);
    }

    //LOGING USER WITH TOKEN.
    public function login(Request $request)
    {
        $validator = Validator::make($request->all(), [
            'email' => 'required|string|email',
            'password' => 'required|string',
        ]);

        if ($validator->fails()) {
            return response(['errors' => $validator->errors()], 422);
        }

        $credentials = \request(['email', 'password']);

        if (Auth::attempt($credentials)) {
            $user = $request->user();
            return $this->getResponse($user);
        }
    }

    //LOGOUT USER.
    public function logout(Request $request)
    {
        $request->user()->token()->revoke();
        return response('Successfully logout!', 200);
    }

    //GET USER.
    public function user(Request $request)
    {
        return $request->user();
    }

    //PRIVATE GET RESPONSE.
    private function getResponse($user)
    {
        //token
        $tokenResult = $user->createToken('Haurizon Pay Token');
        $token = $tokenResult->token;
        $token->expires_at = Carbon::now()->addWeek(1);
        $token->save();

        return response([
            'accessToken' => $tokenResult->accessToken,
            'tokenType' => 'Bearer',
            'expiresAt' => Carbon::parse($token->expires_at)->toDayDateTimeString()
        ], 200);
    }
}
