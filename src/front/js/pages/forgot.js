import React, { useState, useContext } from "react";
import { Context } from "../store/appContext";
import { Link, useHistory } from "react-router-dom";
import { toast } from "react-toastify";

export const RequestResetPass = () => {
	const [email, setEmail] = useState("");
	const [error, setError] = useState("");
	const [message, setMessage] = useState("");
	const history = useHistory();

	function requestResetPass() {
		setError("");
		switch (true) {
			case email.trim() == "":
				setError("Debe escribir un correo.");
				return;
			default:
				break;
		}
		let responseOk = false;
		fetch(process.env.BACKEND_URL + "/api/forgot", {
			method: "POST",
			headers: {
				"Content-Type": "application/json"
			},
			body: JSON.stringify({
				email: email
			})
		})
			.then(response => {
				responseOk = response.ok;
				if (responseOk) {
					if (response.status === 201) {
						toast.success(
							"¡Le hemos enviado un email. En el caso de que no lo haya recibido, es posible que usted no esté registrado en nuestra plataforma!"
						);
					}
				}
				return response.json();
			})
			.then(responseJson => {
				if (responseOk) {
					history.push("/");
				}
			})
			.catch(error => {
				console.log("error", error);
				setError(error.message);
			});
	}

	return (
		<div className="jumbotron">
			{error ? <h3>{error}</h3> : ""}
			{message ? <h3>{message}</h3> : ""}
			<form>
				<input
					type="email"
					placeholder="Ingrese su correo electronico"
					onChange={event => {
						setEmail(event.target.value);
					}}
				/>
				<input type="button" value="Recuperar" onClick={requestResetPass} />
			</form>
		</div>
	);
};
