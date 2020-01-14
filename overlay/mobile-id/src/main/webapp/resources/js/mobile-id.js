MID = (function() {
	var MIDAuth = function() {
		this.selectors = [ '.auth-selection', '.mid-phase-1', '.mid-phase-2' ];
	};
	MIDAuth.prototype.setStageVisibility = function(selector) {
		this.selectors.forEach(function(current) {
			if (current !== selector)
				$(current).addClass('hidden');
			else
				$(current).removeClass('hidden');
		});
	};

	MIDAuth.prototype.showMobileId = function() {
		this.setStageVisibility('.mid-phase-1');
		this.hideError();
	};

	MIDAuth.prototype.cancel = function() {
		if (document.kickstartMID) {
			window.history.back();
		} else {
			this.setStageVisibility('.auth-selection');
		}
	};
	MIDAuth.prototype.showError = function(errorMsg, status) {
		// TODO unify styles
		if (window.CONF_MOBILEID_ERROR_VIA_HREF) {
			// Nortal SSO style
			window.location.href = '?error=mobile&errorCode=' + status;
		} else {
			// Praamid style
			var alert = $('.alert');
			alert.find('.login-error').addClass('hidden');
			alert.find('#' + status).removeClass('hidden');
			alert.removeClass('hidden');
		}
	};

	MIDAuth.prototype.hideError = function() {
		var alert = $('.alert').addClass('hidden');
	};

	MIDAuth.prototype.startAuthentication = function(csrfKey, csrfToken) {
		var mid = this;

		var phoneNr = $('#log-phone').val();
		if (!phoneNr)
			return;

		this.setStageVisibility('.mid-phase-2');

		$.ajax({
			url : 'mobileId?action=start&phone=' + phoneNr,
			type : 'GET',
			dataType : 'JSON',
			cache : false
		}).then(function(result) {
			if(result.status!=='OK') {
				mid.cancel();
				// TODO: translate the codes?
				mid.showError('Mobiil-ID\'ga sisse logimine ebaõnnestus, vea kood: ' + result.status, result.status);
				return;
			}

			$('.mid-challenge-id').html(result.challengeId);
			mid.queueStatusCheck(15000, result.payload, csrfKey, csrfToken);
		}).catch(function(xhr) {
			console.log('MID start error: ' + xhr.status);
			mid.cancel();
		});
	};

	MIDAuth.prototype.queueStatusCheck=function(delay,payload, csrfKey, csrfToken) {
		if(!!this.statusCheckTimeout) clearTimeout(this.statusCheckTimeout);
		this.statusCheckTimeout=setTimeout(this.checkMIDStatus.bind(this,payload, csrfKey, csrfToken), delay);
	};

	MIDAuth.prototype.checkMIDStatus=function(payload, csrfKey, csrfToken) {
		var mid = this;

		if(!payload) {
			console.error('Invalid MID api use, payload is required at this point');
			return;
		}

		console.log(payload);

		$.ajax({
			url: 'mobileId?action=status&payload='+payload,
			type:'GET', dataType:'JSON', cache:false
		}).then(function(result) {
			if(result.status==='USER_AUTHENTICATED') {
				mid.finalizeAuthentication(payload, csrfKey, csrfToken);
				return;
			}

			if(result.status==='OUTSTANDING_TRANSACTION') {
				mid.queueStatusCheck(5000, payload, csrfKey, csrfToken);
				return;
			}

			mid.cancel();
			mid.showError('Mobiil-ID\'ga sisse logimine ebaõnnestus, vea kood: ' + result.status, result.status);
		}).catch(function(xhr) {
			console.log('MID status check error: ' + xhr.status);
			mid.cancel();
		});
	}

	MIDAuth.prototype.finalizeAuthentication=function(payload, csrfKey, csrfToken) {
		var $form = $("<form>")
	        .attr("method", "post")
	        .attr("target", "_self")
	        .attr("action", "mobileId")
	        .attr("id", "sendPostRequestForm");

		var addFormParam = function(name, value) {
	        $("<input type='hidden'>")
	            .attr("name", name)
	            .attr("value", value)
	            .appendTo($form);
	    }

		addFormParam('action', 'finalize');
		addFormParam('payload', payload);
		addFormParam(csrfKey, csrfToken);

	    $form.appendTo("body");
	    $form.submit();
	}

	var mid = new MIDAuth();
	$('#mobileId').click(mid.showMobileId.bind(mid));
        if (document.kickstartMID) {
            mid.showMobileId();
        }
	return mid;
})();