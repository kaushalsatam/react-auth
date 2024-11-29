import React, { createContext, useState } from 'react'
import axios from 'axios'
import URL from '../utils/URL';

export const AuthContext = createContext();

export const AuthProvider = ({children}) => {
    const [user, setUser] = useState(null);
    const [accessToken, setAccessToken] = useState(localStorage.getItem('accessToken'));

    const login = async (email, password) => {
        const response = await axios.post(`${URL}/login`, {email, password});
        setAccessToken(response.data.accessToken);
        localStorage.setItem('accessToken', response.data.accessToken);
        setUser(jwt_decode(response.data.accessToken));

    }

    const logout = () => {
        setAccessToken(null);
        localStorage.removeItem(accessToken);
        setUser(null);
    }

    return (
        <AuthContext.Provider value = {{user, login, logout, accessToken}}>
            {children}
        </AuthContext.Provider>
    )
}