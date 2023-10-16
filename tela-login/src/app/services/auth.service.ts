import { HttpClient } from '@angular/common/http';
import { Injectable } from '@angular/core';
import { Observable } from 'rxjs';
import { User } from '../models/user';

@Injectable({
  providedIn: 'root'
})
export class AuthService {

  readonly url = 'https://localhost:7259/api/Auth/'
  constructor(private http:HttpClient) { }

  public register(user:User):Observable<any>{
    return this.http.post<any>(this.url + "Register", user)
  }

  public login(user:User):Observable<any>{
    return this.http.post(this.url + "Login", user,{
      responseType: 'text',
    })
    
  }

  public getMe():Observable<string>{
    return this.http.get(this.url,{
      responseType: 'text',
    })
  }
}
