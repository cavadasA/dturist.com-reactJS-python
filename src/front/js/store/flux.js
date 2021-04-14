const getState = ({ getStore, getActions, setStore }) => {
	return {
		store: {
			accessToken: "",
			calle: "",
			numero: "",
			ciudad: "",
			codigoPostal: "",
			comunidad: "andalucia",
			dormitorios: "",
			huespedes: "",
			camas: "",
			bathrooms: "",
			descripcion: "",
			fotos: [],
			aire: []
		},
		actions: {
			// Use getActions to call a function within a fuction
			saveAccessToken: accessToken => {
				setStore({ accessToken: accessToken });
				localStorage.setItem("access_token", accessToken);
			},
			getAccessToken: () => {
				let store = getStore();
				if (store.accessToken) {
					return store.accessToken;
				} else {
					return localStorage.getItem("access_token");
				}
			},
			deleteAccessToken: () => {
				let store = getStore();
				setStore({ accessToken: "" });
			},
			setCalle: value => {
				let store = getStore();
				setStore({ calle: value.toLowerCase() });
			},
			setNumero: value => {
				let store = getStore();
				setStore({ numero: value });
			},
			setCiudad: value => {
				let store = getStore();
				setStore({ ciudad: value.toLowerCase() });
			},
			setCodigoPostal: value => {
				let store = getStore();
				setStore({ codigoPostal: value });
			},
			setComunidad: value => {
				let store = getStore();
				setStore({ comunidad: value.toLowerCase() });
			},
			setDormitorios: value => {
				let store = getStore();
				setStore({ dormitorios: value });
			},
			setHuespedes: value => {
				let store = getStore();
				setStore({ huespedes: value });
			},
			setCamas: value => {
				let store = getStore();
				setStore({ camas: value });
			},
			setBathrooms: value => {
				let store = getStore();
				setStore({ bathrooms: value });
			},
			setDescripcion: value => {
				let store = getStore();
				setStore({ descripcion: value });
			},
			setFotos: value => {
				let store = getStore();
				setStore({ fotos: value });
			},
			setAire: value => {
				let store = getStore();
				setStore({ aire: value });
			},

			getFormValues: () => {
				let store = getStore();
				let respuestas = {};
				let calle = store.calle;
				let numero = store.numero;
				let ciudad = store.ciudad;
				let codigoPostal = store.codigoPostal;
				let comunidad = store.comunidad;
				let dormitorios = store.dormitorios;
				let huespedes = store.huespedes;
				let camas = store.camas;
				let bathrooms = store.bathrooms;
				let descripcion = store.descripcion;
				let fotos = store.fotos;
				let aire = store.aire;
				return (respuestas = {
					calle,
					numero,
					ciudad,
					codigoPostal,
					comunidad,
					dormitorios,
					huespedes,
					camas,
					bathrooms,
					descripcion,
					fotos,
					aire
				});
			}
		}
	};
};

export default getState;
