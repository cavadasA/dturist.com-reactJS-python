import React, { useContext, useState, useEffect, Fragment } from "react";
import { useHistory } from "react-router-dom";
import { Context } from "../store/appContext";
import PropTypes from "prop-types";
import { CardAlojamiento } from "../component/cardAlojamiento";
import { CardDescripcion } from "../component/cardDescripcion";

export const MisPropiedades = () => {
	const API_URL = process.env.BACKEND_URL;
	const { actions } = useContext(Context);
	const [misPropiedades, setMisPropiedades] = useState([]);

	useEffect(() => {
		fetch(API_URL + "/api/misPropiedades", {
			method: "GET",
			headers: {
				"Content-Type": "application/json",
				Authorization: "Bearer " + actions.getAccessToken()
			}
		})
			.then(response => response.json())
			.then(responseJson => setMisPropiedades(responseJson));
	}, []);

	return (
		<Fragment>
			<div className="row mt-5 ml-5">
				{misPropiedades.map(propiedad => {
					return (
						<div className="col-4 pb-3" key={propiedad.index}>
							<CardAlojamiento
								key={propiedad.title}
								title={propiedad.titulo}
								huespedes={propiedad.huespedes}
								ciudad={propiedad.ciudad}
								provincia={propiedad.provincia}
								dormitorios={propiedad.dormitorios}
								bathrooms={propiedad.bathrooms}
								id={propiedad.id}
							/>
						</div>
					);
				})}
			</div>

			{/* <div className="row mt-5 ml-5">
				{misPropiedades.map(elemento => {
					return (
						<div className="col-4 pb-3" key={elemento.index}>
							<CardDescripcion
								key={elemento.title}
								title={elemento.titulo}
								huespedes={elemento.huespedes}
								ciudad={elemento.ciudad}
								provincia={elemento.provincia}
								dormitorios={elemento.dormitorios}
								bathrooms={elemento.bathrooms}
								descripcion={elemento.descripcion}
								id={elemento.id}
							/>
						</div>
					);
				})}
			</div> */}
		</Fragment>
	);
};
