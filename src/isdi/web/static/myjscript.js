function updateProgress(percentage, message) {
    var $progress = $('#scan-prog');
    var $wrap = $('#scan-progress-wrap');
    if (!$wrap.length) {
        $wrap = $progress.closest('.progress');
    }
    var $text = $('#scan-progress-text');

    if (!$progress.length) {
        return;
    }

    if ($wrap.length) {
        $wrap.show();
    }
    if (percentage >= 100) {
        percentage = 100;
    }

    $progress.css("width", percentage + "%");
    $progress.attr('aria-valuenow', percentage);
    $progress.text(percentage + "%");

    if ($text.length) {
        if (message) {
            $text.text(message).show();
        } else {
            $text.hide().text('');
        }
    }
}

function resetScanProgress(message) {
    updateProgress(0, message || 'Preparing scan...');
}

function finishScanProgress(message) {
    updateProgress(100, message || 'Scan complete');
}

function pollScanStatus(statusUrl, resultUrl, $button) {
    var pollDelay = 1000;
    var timer = window.setInterval(function () {
        $.getJSON(statusUrl)
            .done(function (state) {
                if (!state) {
                    return;
                }
                updateProgress(state.percent || 0, state.message || state.step || 'Scanning...');

                if (state.status === 'done') {
                    window.clearInterval(timer);
                    finishScanProgress(state.message || 'Scan complete');
                    window.location.href = resultUrl;
                } else if (state.status === 'error') {
                    window.clearInterval(timer);
                    if ($button && $button.length) {
                        $button.prop('disabled', false).text($button.data('original-text') || 'Scan now');
                    }
                    updateProgress(0, state.error || state.message || 'Scan failed');
                    report_failure(state.error || state.message || 'Scan failed');
                }
            })
            .fail(function () {
                window.clearInterval(timer);
                if ($button && $button.length) {
                    $button.prop('disabled', false).text($button.data('original-text') || 'Scan now');
                }
                updateProgress(0, 'Could not read scan status.');
                report_failure('Could not read scan status.');
            });
    }, pollDelay);
}

function startScan(form) {
    var $form = $(form);
    var $button = $form.find('button[type=submit]').first();

    if (!$form.length) {
        return true;
    }

    if ($button.length) {
        $button.data('original-text', $button.text());
        $button.prop('disabled', true).text('Scanning...');
    }

    resetScanProgress('Starting scan...');
    $.post('/scan/start', $form.serialize())
        .done(function (resp) {
            if (!resp || !resp.status_url || !resp.result_url) {
                if ($button.length) {
                    $button.prop('disabled', false).text($button.data('original-text') || 'Scan now');
                }
                report_failure('Could not start the scan.');
                updateProgress(0, 'Could not start the scan.');
                return;
            }

            updateProgress(5, 'Scan started.');
            pollScanStatus(resp.status_url, resp.result_url, $button);
        })
        .fail(function (xhr) {
            if ($button.length) {
                $button.prop('disabled', false).text($button.data('original-text') || 'Scan now');
            }

            var message = 'Could not start the scan.';
            if (xhr.responseJSON && xhr.responseJSON.error) {
                message = xhr.responseJSON.error;
            }
            updateProgress(0, message);
            report_failure(message);
        });

    return false;
}

function delete_app(appid, e) {
    // Removing an app can destroy evidence that it was installed and what
    // it did. Say so before every uninstall, not only for flagged apps.
    y = confirm(
        `Uninstall '${appid}'?\n\n` +
        'Removing an app can destroy evidence. If this may be used in court ' +
        '(protective order, family or criminal case), keep an evidence copy of ' +
        'the scan first, and consider leaving the app in place until a lawyer ' +
        'or advocate has been consulted. Removing monitoring software can also ' +
        'alert the person who installed it; plan for safety first.\n\n' +
        'Uninstall now?'
    );
    if (!y){return;}
    data = {'appid': appid, 'serial': serial, 'device': device};
    $.post('/delete/app/' + scanid, data=data).done(function (r){
        $('tr#' + appid.replace(/\./g, '-')).addClass('text-muted');
        $(e).removeClass('text-warning');
        $(e).addClass('text-success');
        $(e).html('&#10003;');
        $(e).removeAttr('data-action');
        report_success(r);
    }).fail(function(){
        report_failure("Could not delete the app '" + appid + "'")
    })
}


/* Event wiring. The Content-Security-Policy blocks inline on* handlers, so
   templates mark elements with data-action and the handlers live here. */
$(document).on('click', '[data-action]', function (e) {
    var $el = $(this);
    switch ($el.attr('data-action')) {
        case 'close-app':
            e.preventDefault();
            close_isdi();
            break;
        case 'close-window':
            e.preventDefault();
            close_window($el.attr('data-confirm'));
            break;
        case 'delete-app':
            e.preventDefault();
            delete_app($el.attr('data-appid'), this);
            break;
        case 'print':
            e.preventDefault();
            window.print();
            break;
        case 'privacy-get':
            e.preventDefault();
            get($el.attr('data-url'));
            break;
    }
});

$(document).on('submit', 'form[data-action="start-scan"]', function (e) {
    if (startScan(this) === false) {
        e.preventDefault();
    }
});

$(document).on('submit', 'form[data-confirm]', function (e) {
    if (!confirm($(this).attr('data-confirm'))) {
        e.preventDefault();
    }
});

// Signed-in sessions end after a period without requests (automatic
// logoff). Typing or clicking counts as activity, so a long form being
// filled in is not lost: tell the server, at most once a minute.
(function () {
    var last = Date.now();
    function active() {
        if (Date.now() - last < 60000) {
            return;
        }
        last = Date.now();
        $.get('/session/ping');
    }
    $(document).on('keydown click', active);
})();
