import React, { useContext, useState, useEffect, Fragment } from "react";
import PropTypes from "prop-types";
import { Context } from "../store/appContext";
import { Link, useParams, useLocation } from "react-router-dom";
import "../../styles/descripcionMisPropiedades.scss";
import ratings from "../../img/ratings.jpg";
import { MisPropiedades } from "./misPropiedades";
import { DateRangePicker, START_DATE, END_DATE } from "react-nice-dates";
import { es } from "date-fns/locale";
import "react-nice-dates/build/style.css";

export const DescripcionPropiedades = props => {
	const API_URL = process.env.BACKEND_URL;
	const [startDate, setStartDate] = useState(0);
	const [endDate, setEndDate] = useState(0);
	const { actions } = useContext(Context);
	const location = useLocation();
	const params = useParams();
	const [propiedad, setPropiedad] = useState(props.location.state);
	let arrayAmenidades = [];
	const oneDay = 24 * 60 * 60 * 1000;
	const diffDays = Math.round(Math.abs((startDate - endDate) / oneDay));
	let precioFinal = diffDays * propiedad.precio;

	return (
		<Fragment>
			<div className="container marginDescripcion bg-white esquinasRedondas">
				<div className="row pt-2">
					<div className="col-8 bg-white centraje px-5 pt-0 pb-3 esquinasRedondas">
						<div className="form-group row ">
							<div className=" row ">
								<div className="col-md-12 row contenedorNombreAlojamiento">
									<div className="contenedorTitulo row ">
										<i className="fas fa-home mt-2 ml-2 pl-1 color sizeCasa "></i>
										<h4 className="pt-1 pl-1">{propiedad.title}</h4>
										<img src={ratings} width="121px" height="31px" className="pl-3 pt-2 " />
									</div>
									<div className="contenedorLikes mt-2">
										<i className="far fa-thumbs-up pt-2 pl-1 color sizeCasa"></i>
										<i className="far fa-heart pt-2  pl-3 color sizeCasa"></i>
										<i className="fas fa-share-alt pt-2  pl-3 color sizeCasa"></i>
									</div>
								</div>
								<div className="col-md-6 mt-2 row contenedorNombreProvincia">
									<i className="fas fa-map-marker-alt pt-2 color sizeUbicacion"></i>
									<p className="pt-1 ml-3 sizeTextCiudad">
										{propiedad.ciudad}, {propiedad.provincia} (España)
									</p>
								</div>
							</div>

							<div className="col-md-12 mt-3">
								<div id="carouselExampleCaptions" className="carousel slide" data-ride="carousel">
									<ol className="carousel-indicators">
										<li
											data-target="#carouselExampleCaptions"
											data-slide-to="0"
											className="active"></li>
										<li data-target="#carouselExampleCaptions" data-slide-to="1"></li>
										<li data-target="#carouselExampleCaptions" data-slide-to="2"></li>
									</ol>
									<div className="carousel-inner">
										<div className="carousel-item active">
											<img
												src="https://i.pinimg.com/originals/14/14/a0/1414a076665216ea2f641f7d046eab09.jpg"
												width="500px"
												height="400px"
												className="d-block w-100"
												alt="..."
											/>
											<div className="carousel-caption d-none d-md-block">
												<h5>First slide label</h5>
												<p>Nulla vitae elit libero, a pharetra augue mollis interdum.</p>
											</div>
										</div>
										<div className="carousel-item">
											<img
												src="https://cf.bstatic.com/images/hotel/max1024x768/191/191209039.jpg"
												width="500px"
												height="400px"
												className="d-block w-100"
												alt="..."
											/>
											<div className="carousel-caption d-none d-md-block">
												<h5>Second slide label</h5>
												<p>Lorem ipsum dolor sit amet, consectetur adipiscing elit.</p>
											</div>
										</div>
										<div className="carousel-item">
											<img
												src="https://casaydiseno.com/wp-content/uploads/2016/12/casas-rurales-decoracion-interior.jpg"
												width="500px"
												height="400px"
												className="d-block w-100"
												alt="..."
											/>
											<div className="carousel-caption d-none d-md-block">
												<h5>Third slide label</h5>
												<p>Praesent commodo cursus magna, vel scelerisque nisl consectetur.</p>
											</div>
										</div>
									</div>
								</div>
								<a
									className="carousel-control-prev"
									href="#carouselExampleCaptions"
									role="button"
									data-slide="prev">
									<span className="carousel-control-prev-icon" aria-hidden="true"></span>
									<span className="sr-only">Previous</span>
								</a>
								<a
									className="carousel-control-next"
									href="#carouselExampleCaptions"
									role="button"
									data-slide="next">
									<span className="carousel-control-next-icon" aria-hidden="true"></span>
									<span className="sr-only">Next</span>
								</a>
							</div>
						</div>
						<div className="row">
							<i className="fas fa-map-marker-alt ml-3 pt-1 text-primary  "></i>
							<p className=" pl-2 sizeText">
								Calle {propiedad.calle} número {propiedad.numero}, {propiedad.codigo_postal},{" "}
								{propiedad.ciudad} {propiedad.provincia}
							</p>
							<p className="text-primary pl-2 sizeText">
								<strong>-Excelente Ubicación</strong>
							</p>
							<p className="text-primary sizeText">
								<strong>-ver mapa</strong>
							</p>
						</div>
						<hr></hr>
						<div className="row justificado color ">
							<div className="items">
								<i className="fas fa-bath color sizeCasa"></i>
								<p className="#"> {propiedad.bathrooms} Baños</p>
							</div>
							<div className="items">
								<i className="fas fa-users color sizeCasa"></i>
								<p className="#"> {propiedad.huespedes} Personas</p>
							</div>
							<div className="items">
								<i className="fas fa-bed color sizeCasa"></i>
								<p className="#">{propiedad.dormitorios} Dormitorios</p>
							</div>
							<div className="items">
								<i className="fas fa-paw color sizeCasa"></i>
								<p className="#"> Mascotas</p>
							</div>
						</div>
						<div className="row">
							<div className="col-md-12 mt-3">
								<div className="row contenedorServicios pr-5">
									<h6 className="#">
										<strong>Servicios</strong>
									</h6>
									<ul className="#">
										<hr></hr>
										{propiedad.amenidades.map((amenidades, index) => {
											return (
												<i
													key={index}
													className="column far fa-check-circle color sizeItems pt-1 pl-5">
													{" "}
													{amenidades}
												</i>
											);
										})}
									</ul>
								</div>
							</div>
						</div>
						<div className="form-group row ">
							<div className="col-md-12 mt-3 mb-3 contenedorDescripcion">
								<div className="row">
									<h6 className="#">
										<strong>Descripción</strong>
									</h6>
								</div>
								<hr></hr>
								<p>{propiedad.descripcion}</p>
							</div>
						</div>
						<div className="form-group row ">
							<div className="col-md-12 mt-3 mb-3 contenedorDescripcion">
								<div className="row">
									<h6 className="#">
										<strong>Precios</strong>
									</h6>
								</div>
								<hr></hr>
								<div className="row pl-3">
									<div className="col-6">
										<p>{propiedad.precio}€ la noche</p>
										{startDate === 0 || startDate === null ? (
											<p>0 noches seleccionadas</p>
										) : endDate === 0 || endDate === null ? (
											<p>0 noches seleccionadas</p>
										) : (
											<p>{diffDays} noches seleccionadas</p>
										)}
										<p className="d-inline-block">
											<strong>Total: </strong>
										</p>
										{startDate === 0 || startDate === null ? (
											<p className="d-inline-block">&nbsp;0€</p>
										) : endDate === 0 || endDate === null ? (
											<p className="d-inline-block">&nbsp;0€</p>
										) : (
											<p className="d-inline-block">&nbsp;{precioFinal}€</p>
										)}
									</div>
									<div className="col-6">
										<button type="button" className="btn botonReservaAhora " value="crear">
											<strong>Reserva ahora</strong>
										</button>
									</div>
								</div>
								<div className="row mt-3">
									<div className="col-12">
										<DateRangePicker
											startDate={startDate}
											endDate={endDate}
											onStartDateChange={setStartDate}
											onEndDateChange={setEndDate}
											minimumDate={new Date()}
											minimumLength={1}
											format="dd/MM/yyyy"
											locale={es}>
											{({ startDateInputProps, endDateInputProps, focus }) => (
												<div className="date-range">
													<div className="col-6 d-inline-block">
														<label htmlFor="llegada">Llegada</label>
														<input
															className={
																"form-control input" +
																(focus === START_DATE ? " -focused" : "")
															}
															id="llegada"
															{...startDateInputProps}
															placeholder="dd/mm/aaaa"
															autoComplete="off"
														/>
													</div>

													<div className="col-6 d-inline-block">
														<label htmlFor="salida">Salida</label>
														<input
															className={
																" form-control input" +
																(focus === END_DATE ? " -focused" : "")
															}
															id="salida"
															{...endDateInputProps}
															placeholder="dd/mm/aaaa"
															autoComplete="off"
														/>
													</div>
												</div>
											)}
										</DateRangePicker>
									</div>
								</div>
							</div>
						</div>

						<div className="form-group row ">
							<div className="col-md-12 mt-3 mb-3">
								<p>
									4 motivos para elegir <strong>{propiedad.titulo}</strong>
								</p>
								<div className="contenedorElegir column sizeItems color">
									<div className="posicioPrimeraFila row">
										<div className="unionText row">
											<i className="far fa-check-circle pt-1"></i>
											<p className="pl-1">¡Precios imbatibles!</p>
										</div>
										<div className="unionText row">
											<i className="far fa-check-circle pt-1"></i>
											<p className="pl-1">Gestiona tus reservas online</p>
										</div>
									</div>

									<div className="posicioPrimeraFila row">
										<div className="unionText row">
											<i className="far fa-check-circle pt-1"></i>
											<p className="pl-1">Hablan 3 idiomas</p>
										</div>
										<div className="unionText row">
											<i className="far fa-check-circle pt-1"></i>
											<p className="pl-1">Una reserva segura</p>
										</div>
									</div>
								</div>
							</div>
						</div>

						<div className="form-group row ">
							<div className="col-md-12 mb-3 contenedorDescripcion">
								<div className="row">
									<h6 className="#">
										<strong>Info importante</strong>
									</h6>
								</div>
								<hr></hr>
								<p>
									Según las indicaciones del Gobierno para minimizar el contagio del coronavirus
									(COVID-19), es posible que este alojamiento solicite documentación adicional a los
									clientes para comprobar su identidad, itinerario de viaje y otros datos relevantes
									mientras sigan vigentes dichas indicaciones. En respuesta al coronavirus (COVID-19),
									el alojamiento aplica medidas sanitarias y de seguridad adicionales en estos
									momentos. Los servicios de comida y bebida de este alojamiento pueden verse
									limitados o no estar disponibles a causa del coronavirus (COVID-19). A causa del
									coronavirus (COVID-19), este alojamiento está tomando medidas para garantizar la
									seguridad de los clientes y el personal. Por este motivo, algunos servicios e
									instalaciones pueden verse limitados o no estar disponibles. Debido al coronavirus
									(COVID-19), es obligatorio llevar mascarilla en todas las zonas comunes interiores.
								</p>
							</div>
						</div>
					</div>
				</div>
			</div>
		</Fragment>
	);
};

DescripcionPropiedades.propTypes = {
	location: PropTypes.shape({
		pathname: PropTypes.string.isRequired,
		state: PropTypes.object
	}).isRequired
};
