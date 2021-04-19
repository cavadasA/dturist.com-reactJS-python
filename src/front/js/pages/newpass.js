import React, { useState, useContext } from "react";
import { Context } from "../store/appContext";
import { useHistory, Link } from "react-router-dom";

//validacines y notificaciones
import SimpleReactValidator from "simple-react-validator";
import { toast } from "react-toastify";

//vistas
import Grid from "@material-ui/core/Grid";
import TextField from "@material-ui/core/TextField";
import Button from "@material-ui/core/Button";

import "../../styles/signup.scss";

export const ResetPass = () => {
	const history = useHistory();
	const [value, setValue] = useState({
		email: "",
		password: "",
		confirm_password: ""
	});
	const changeHandler = e => {
		setValue({ ...value, [e.target.name]: e.target.value });
		validator.showMessages();
	};

	const [validator] = React.useState(
		new SimpleReactValidator({
			className: "errorMessage"
		})
	);

	let search = window.location.search;
	let params = new URLSearchParams(search);
	let token = params.get("token");

	const submitForm = e => {
		e.preventDefault();
		if (validator.allValid()) {
			let responseOk = false;
			fetch(process.env.BACKEND_URL + "/api/newpass", {
				method: "POST",
				headers: {
					"Content-Type": "application/json"
				},
				body: JSON.stringify({
					email: value.email,
					password: value.password,
					token: token
				})
			})
				.then(response => {
					responseOk = response.ok;
					if (response.ok) {
						if (response.status === 201) {
							setValue({
								email: "",
								password: "",
								confirm_password: ""
							});
							validator.hideMessages();
							history.push("/login");
							toast.success("Contraseña cambiada correctamente");
						}
					}
					return response.json();
				})
				.then(responseJson => {
					if (!responseOk) {
						toast.error(responseJson.message);
					}
				})
				.catch(error => {
					console.log("error", error);
					toast.error(error.message);
				});
		} else {
			validator.showMessages();
			toast.error("No puede estar vacio!");
		}
	};

	return (
		<Grid className="loginWrapper">
			<Grid className="loginForm">
				<h2>Reset Password</h2>
				<p>Fill your email and new password</p>
				<form onSubmit={submitForm}>
					<Grid container spacing={3}>
						<Grid item xs={12}>
							<TextField
								className="inputOutline"
								fullWidth
								placeholder="E-mail"
								value={value.email}
								variant="outlined"
								name="email"
								label="E-mail"
								InputLabelProps={{
									shrink: true
								}}
								onBlur={e => changeHandler(e)}
								onChange={e => changeHandler(e)}
							/>
							{validator.message("email", value.email, "required|email")}
						</Grid>
						<Grid item xs={12}>
							<TextField
								className="inputOutline"
								fullWidth
								placeholder="New Password"
								value={value.password}
								variant="outlined"
								name="password"
								label="Password"
								InputLabelProps={{
									shrink: true
								}}
								onBlur={e => changeHandler(e)}
								onChange={e => changeHandler(e)}
							/>
							{validator.message("password", value.password, "required")}
						</Grid>
						<Grid item xs={12}>
							<TextField
								className="inputOutline"
								fullWidth
								placeholder="Confirm Password"
								value={value.password}
								variant="outlined"
								name="confirm_password"
								label="Confirm Password"
								InputLabelProps={{
									shrink: true
								}}
								onBlur={e => changeHandler(e)}
								onChange={e => changeHandler(e)}
							/>
							{validator.message("confirm password", value.confirm_password, `in:${value.password}`)}
						</Grid>
						<Grid item xs={12}>
							<Grid className="formFooter">
								<Button fullWidth className="cBtn cBtnLarge cBtnTheme" type="submit">
									Send
								</Button>
							</Grid>
						</Grid>
					</Grid>
				</form>
			</Grid>
		</Grid>
	);
};
