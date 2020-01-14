<%@ taglib prefix="authz" uri="http://www.springframework.org/security/tags"%>
<%@ taglib prefix="c" uri="http://java.sun.com/jsp/jstl/core"%>
<%@ taglib prefix="o" tagdir="/WEB-INF/tags"%>
<%@ taglib prefix="spring" uri="http://www.springframework.org/tags"%>

<o:header title="Log In" />
<script type="text/javascript">
<!--

$(document).ready(function() {
	// select the appropriate field based on context
	$('#<c:out value="${ login_hint != null ? 'j_password' : 'j_username' }" />').focus();
});

//-->
</script>
<o:topbar />
<div class="container main" id="login">

	<div class="action">
		<div class="row-fluid">
			<div class="span4">
				<div class="box">
					<h2><spring:message code="login.login_with_username_and_password"/></h2>

					<c:if test="${ param.error != null }">
						<div class="alert alert-error"><spring:message code="login.error"/></div>
					</c:if>
							<div class="content">
							<form
								action="${ config.issuer }${ config.issuer.endsWith('/') ? '' : '/' }j_spring_security_check"
								method="POST">
								<div>
									<div class="input-prepend input-block-level">
										<span class="add-on"><i class="icon-user"></i></span> <input
											type="text" placeholder="Username" autocorrect="off"
											autocapitalize="off" autocomplete="off" spellcheck="false"
											value="<c:out value="${ login_hint }" />" id="j_username" name="j_username">
									</div>
								</div>
								<div>
									<div class="input-prepend input-block-level">
										<span class="add-on"><i class="icon-lock"></i></span> <input
											type="password" placeholder="Password" autocorrect="off"
											autocapitalize="off" autocomplete="off" spellcheck="false"
											id="j_password" name="j_password">
									</div>
								</div>
								<div>
									<input type="hidden" name="${_csrf.parameterName}" value="${_csrf.token}" />
									<input type="submit" class="btn" value="Login" name="submit">
								</div>
							</form>
							</div>
				</div>
			</div>
			<div class="span4">
				<div class="box">
					<h2>Login with Google+</h2>
					<div class="content">
						<p>Authenticate with your Google+ account.</p>
						<a href="${Google2ClientLoginUrl}"> <img
							src="https://developers.google.com/+/images/branding/sign-in-buttons/Red-signin_Medium_base_44dp.png"
							style="width: 120px; height: 40px;">
						</a>
					</div>
				</div>
			</div>
			<div class="span4">
				<div class="box">
					<h2>Login with Facebook</h2>
					<div class="content">
						<p>Authenticate with your Facebook account.</p>
						<a href="${FacebookClientLoginUrl}"> <img
							src="resources/images/fb.png" style="height: 40px;" />
						</a>
					</div>
				</div>
			</div>
		</div>
	</div>



</div>

<o:footer />
