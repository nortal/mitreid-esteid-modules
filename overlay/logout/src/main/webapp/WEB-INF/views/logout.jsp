<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="security" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<spring:message code="logout.title" var="title"/>
<o:header title="${title}"/>
<o:topbar pageName="Logout"/>
<div class="container-fluid main">
	<div class="row-fluid">
		<div class="span1"></div>
		<div class="span10">
            <security:authorize access="hasRole('ROLE_USER')">
				<div class="hero-unit">
					<h2><spring:message code="logout.title"/></h2>
					<p>
						<spring:message code="logout.body"/>
					</p>
					<p>
		                <form action="${ config.issuer }${ config.issuer.endsWith('/') ? '' : '/' }logout" method="POST" id="endSessionLogoutForm">
							<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
							<spring:message code="topbar.logout" var="submitText"/>
							<input type="submit" class="btn btn-primary btn-large" value="${submitText}"/>
						</form>
					</p>
				</div>
            </security:authorize>
		</div>
	</div>
</div>
<o:footer/>