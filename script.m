clc;
clear;
close all;

%% =====================================================
%  DDoS ATTACK DETECTION DASHBOARD - v3
%  New features added on top of v2:
%   1. ML-based anomaly detection (from-scratch mini
%      Isolation Forest, no toolboxes required)
%   2. Multi-source / botnet attack simulation
%      (3-6 simulated attacker IPs per attack tick,
%      traffic load shared across them)
%   3. Simulated Geo-IP heat map (6 illustrative regions,
%      bubble size = offenses, color = traffic volume)
%   4. Side-by-side Rule-based vs ML-based accuracy report
%   5. Region-based attack origin bar chart
%  (all v2 features retained: adaptive threshold, CSV log,
%   IP blacklist, top-offenders chart, audible alert,
%   attack duration stats, protocol simulation, session
%   timer, final .txt report)
%% =====================================================

%% SETTINGS
threshold        = 1000;   % fixed threshold (packets/sec)
blacklistLimit   = 3;      % offenses before an IP is auto-blocked
adaptiveWindow   = 8;      % samples used for adaptive threshold
mlAnomalyThresh  = 0.62;   % isolation-forest score above this = anomaly
isoTrees         = 50;     % number of random trees in mini isolation forest
isoSampleSize    = 8;      % points sampled per tree
botMin           = 3;      % min simultaneous attacker IPs during an attack
botMax           = 6;      % max simultaneous attacker IPs during an attack

attackCount      = 0;
normalCount      = 0;
blockedCount     = 0;

% Ground truth: we know the simulated attack occurs in this window,
% used later purely to score how well each detector performed.
groundTruthStart = 25;
groundTruthEnd   = 35;

% History buffers
trafficHistory = [];
timeHistory    = [];
ipOffenseCount = zeros(1,255);   % offense tally per simulated IP
blacklist      = [];             % blocked IP list
protocolCounts = struct('TCP',0,'UDP',0,'ICMP',0);

peakTraffic    = 0;
peakTime       = 0;
attackStartT   = NaN;
attackSegments = [];   % [startTime endTime] rows
botSizeHistory = [];   % botnet size recorded on each attack tick

% Confusion-matrix counters, rule-based detector
TP = 0; FP = 0; TN = 0; FN = 0;
% Confusion-matrix counters, ML detector
TP2 = 0; FP2 = 0; TN2 = 0; FN2 = 0;

%% GEO-IP REGION SETUP (simulated / illustrative, not real geolocation)
regions      = {'N. America','S. America','Europe','Africa','Asia','Oceania'};
regionX      = [2.0 3.0 5.0 5.0 7.5 8.0];
regionY      = [7.5 3.0 8.0 4.0 7.0 2.0];
regionOffenseCount = zeros(1,6);
regionTrafficSum   = zeros(1,6);
regionOf = @(ip) mod(ip-1,6) + 1;

%% LOG FILE SETUP
logFile = fopen('traffic_log.csv','w');
fprintf(logFile,'Time,Traffic,SourceIP,Region,Protocol,Status,Severity,NetworkHealth,MLAnomalyScore,ActiveBots\n');

sessionStartTime = tic;

%% CREATE DASHBOARD
figure('Name','DDoS Attack Detection Dashboard v3',...
       'NumberTitle','off',...
       'Position',[60 40 1250 780]);

%% Traffic axes (top-left, main plot)
ax1 = axes('Position',[0.07 0.38 0.62 0.56]);
h = animatedline(ax1,'Color','b','LineWidth',2,'DisplayName','Traffic');
hAdapt = animatedline(ax1,'Color',[0.9 0.5 0],'LineStyle',':','LineWidth',1.5,...
       'DisplayName','Adaptive Threshold');
xlabel(ax1,'Time (s)');
ylabel(ax1,'Packets/sec');
title(ax1,'Real-Time Network Traffic Monitoring');
grid(ax1,'on');
hold(ax1,'on');
yline(ax1,threshold,'r--','Fixed Threshold');
xlim(ax1,[0 50]);
ylim(ax1,[0 3000]);
legend(ax1,'Location','northwest');

%% Geo-IP heat map axes (bottom-left)
ax2 = axes('Position',[0.07 0.06 0.62 0.26]);
hold(ax2,'on');
hGeo = scatter(ax2, regionX, regionY, 60*ones(1,6), zeros(1,6), 'filled');
colormap(ax2,'hot');
caxis(ax2,[0 1]);
for k = 1:numel(regions)
    text(ax2, regionX(k), regionY(k)-0.9, regions{k}, ...
        'FontSize',8,'HorizontalAlignment','center');
end
xlim(ax2,[0 10]);
ylim(ax2,[0 10]);
axis(ax2,'off');
title(ax2,'Simulated Geo-IP Origin Heat Map (illustrative regions)');

%% STATUS BOXES (right column)
statusBox = annotation('textbox',[0.73 0.87 0.25 0.055],...
    'String','STATUS: NORMAL','FitBoxToText','on',...
    'FontSize',12,'FontWeight','bold');

severityBox = annotation('textbox',[0.73 0.81 0.25 0.055],...
    'String','SEVERITY: NONE','FitBoxToText','on',...
    'FontSize',12,'FontWeight','bold');

mlBox = annotation('textbox',[0.73 0.75 0.25 0.055],...
    'String','ML ANOMALY: 0.00 (normal)','FitBoxToText','on',...
    'FontSize',12,'FontWeight','bold');

healthBox = annotation('textbox',[0.73 0.69 0.25 0.055],...
    'String','NETWORK HEALTH: 100%','FitBoxToText','on',...
    'FontSize',12,'FontWeight','bold');

blacklistBox = annotation('textbox',[0.73 0.63 0.25 0.055],...
    'String','BLOCKED IPs: 0','FitBoxToText','on',...
    'FontSize',12,'FontWeight','bold');

botsBox = annotation('textbox',[0.73 0.57 0.25 0.055],...
    'String','ACTIVE BOTS: 0','FitBoxToText','on',...
    'FontSize',12,'FontWeight','bold');

timerBox = annotation('textbox',[0.73 0.51 0.25 0.055],...
    'String','ELAPSED: 0.0s','FitBoxToText','on',...
    'FontSize',12,'FontWeight','bold');

set(gcf,'Visible','on');
drawnow;   % force the dashboard to render immediately, before the loop starts

fprintf('\n');
fprintf('=====================================\n');
fprintf(' DDoS ATTACK DETECTION SYSTEM STARTED\n');
fprintf('=====================================\n\n');

%% SIMULATION LOOP
for t = 1:50

    isGroundTruthAttack = (t >= groundTruthStart && t <= groundTruthEnd);

    % --- Traffic + Source IP generation ---
    if isGroundTruthAttack
        % Botnet: several attacker IPs active simultaneously, sharing load
        botSize = randi([botMin botMax]);
        attackerIPs = unique(randi([1 255],1,botSize));
        botSize = numel(attackerIPs);
        traffic = randi([1500 2500]);   % aggregate traffic this tick

        r = rand(1,botSize);
        shares = round(traffic * r ./ sum(r));
        shares(end) = shares(end) + (traffic - sum(shares));
        shares(shares < 0) = 0;
    else
        botSize = 0;
        attackerIPs = randi([1 255]);
        traffic = randi([200 700]);
        shares = traffic;
    end
    ip = attackerIPs(1);   % primary IP, kept for compatibility / single-IP logging

    botSizeHistory(end+1) = botSize; %#ok<SAGROW>

    % --- Update History ---
    trafficHistory(end+1) = traffic; %#ok<SAGROW>
    timeHistory(end+1)    = t;       %#ok<SAGROW>

    % --- Adaptive Threshold (mean + 3*std of recent window) ---
    if numel(trafficHistory) >= 3
        windowData = trafficHistory(max(1,end-adaptiveWindow+1):end);
        adaptiveThreshold = mean(windowData) + 3*std(windowData);
    else
        adaptiveThreshold = threshold;
    end

    % --- ML Anomaly Detection (mini Isolation Forest) ---
    if numel(trafficHistory) >= 5
        historyBeforeNow = trafficHistory(1:end-1);
        recentWindow = historyBeforeNow(max(1,end-adaptiveWindow+1):end);
        if numel(recentWindow) >= 3
            mlScore = isoForestScore(traffic, recentWindow, isoTrees, ...
                min(isoSampleSize, numel(recentWindow)));
        else
            mlScore = 0.5;
        end
    else
        mlScore = 0.5;
    end
    isMLAnomaly = mlScore > mlAnomalyThresh;

    % --- Plot Traffic ---
    addpoints(h, t, traffic);
    addpoints(hAdapt, t, adaptiveThreshold);

    % --- Track Peak ---
    if traffic > peakTraffic
        peakTraffic = traffic;
        peakTime = t;
    end

    % --- Calculate Health ---
    health = max(0, 100 - round(traffic/30));

    % --- Detection Logic (fixed threshold drives the alert system) ---
    isDetectedAttack = traffic > threshold;

    if isDetectedAttack
        attackCount = attackCount + 1;

        if isnan(attackStartT)
            attackStartT = t;
            try
                beep;
            catch
            end
        end

        if traffic > 2000
            severity = 'HIGH';
        elseif traffic > 1500
            severity = 'MEDIUM';
        else
            severity = 'LOW';
        end

        % Offense tracking + auto-blacklist for every participating bot
        blockedNote = '';
        for bi = 1:numel(attackerIPs)
            bip = attackerIPs(bi);
            ipOffenseCount(bip) = ipOffenseCount(bip) + 1;
            regionOffenseCount(regionOf(bip)) = regionOffenseCount(regionOf(bip)) + 1;
            regionTrafficSum(regionOf(bip)) = regionTrafficSum(regionOf(bip)) + shares(bi);
            if ipOffenseCount(bip) >= blacklistLimit && ~ismember(bip, blacklist)
                blacklist(end+1) = bip; %#ok<SAGROW>
                blockedCount = blockedCount + 1;
                blockedNote = ' [AUTO-BLOCKED]';
            end
        end

        set(statusBox,'String','STATUS: ATTACK DETECTED',...
            'BackgroundColor',[1 0.7 0.7]);
        set(severityBox,'String',['SEVERITY: ' severity]);

        fprintf('[ALERT] Time %d\n', t);
        fprintf('Traffic     : %d Packets/sec (botnet size %d)\n', traffic, botSize);
        fprintf('Attacker IPs: %s%s\n', strjoin(arrayfun(@(x) sprintf('192.168.1.%d',x), ...
            attackerIPs, 'UniformOutput', false), ', '), blockedNote);
        fprintf('Severity    : %s\n\n', severity);

        status = 'ATTACK';
    else
        normalCount = normalCount + 1;

        regionTrafficSum(regionOf(ip)) = regionTrafficSum(regionOf(ip)) + traffic;

        if ~isnan(attackStartT)
            attackSegments(end+1,:) = [attackStartT, t-1]; %#ok<SAGROW>
            attackStartT = NaN;
        end

        set(statusBox,'String','STATUS: NORMAL',...
            'BackgroundColor',[0.7 1 0.7]);
        set(severityBox,'String','SEVERITY: NONE');

        fprintf('[INFO] Time %d\n', t);
        fprintf('Traffic   : %d Packets/sec\n', traffic);
        fprintf('Source IP : 192.168.1.%d\n\n', ip);

        status = 'NORMAL';
        severity = 'NONE';
    end

    % --- ML anomaly status box ---
    if isMLAnomaly
        set(mlBox,'String',sprintf('ML ANOMALY: %.2f (ANOMALY)', mlScore),...
            'BackgroundColor',[1 0.8 0.6]);
    else
        set(mlBox,'String',sprintf('ML ANOMALY: %.2f (normal)', mlScore),...
            'BackgroundColor',[0.9 0.9 0.9]);
    end

    % --- Confusion Matrix: rule-based vs ground truth ---
    if isDetectedAttack && isGroundTruthAttack
        TP = TP + 1;
    elseif isDetectedAttack && ~isGroundTruthAttack
        FP = FP + 1;
    elseif ~isDetectedAttack && isGroundTruthAttack
        FN = FN + 1;
    else
        TN = TN + 1;
    end

    % --- Confusion Matrix: ML detector vs ground truth ---
    if isMLAnomaly && isGroundTruthAttack
        TP2 = TP2 + 1;
    elseif isMLAnomaly && ~isGroundTruthAttack
        FP2 = FP2 + 1;
    elseif ~isMLAnomaly && isGroundTruthAttack
        FN2 = FN2 + 1;
    else
        TN2 = TN2 + 1;
    end

    % --- Update Boxes ---
    set(healthBox,'String',['NETWORK HEALTH: ' num2str(health) '%']);
    set(blacklistBox,'String',['BLOCKED IPs: ' num2str(numel(blacklist))]);
    set(botsBox,'String',['ACTIVE BOTS: ' num2str(botSize)]);
    elapsed = toc(sessionStartTime);
    set(timerBox,'String',['ELAPSED: ' num2str(elapsed,'%.1f') 's']);

    % --- Update Geo-IP heat map bubbles ---
    sizes = 60 + regionOffenseCount*50;
    set(hGeo,'SizeData',sizes,'CData',regionTrafficSum);
    if max(regionTrafficSum) > 0
        caxis(ax2,[0 max(regionTrafficSum)]);
    end

    drawnow;

    % --- Write to CSV log (one row per attacker IP during attacks) ---
    if isDetectedAttack
        for bi = 1:numel(attackerIPs)
            protoRoll = rand();
            if protoRoll < 0.5
                protocol = 'TCP'; protocolCounts.TCP = protocolCounts.TCP + 1;
            elseif protoRoll < 0.8
                protocol = 'UDP'; protocolCounts.UDP = protocolCounts.UDP + 1;
            else
                protocol = 'ICMP'; protocolCounts.ICMP = protocolCounts.ICMP + 1;
            end
            fprintf(logFile,'%d,%d,192.168.1.%d,%s,%s,%s,%s,%d,%.2f,%d\n',...
                t, shares(bi), attackerIPs(bi), regions{regionOf(attackerIPs(bi))}, ...
                protocol, status, severity, health, mlScore, botSize);
        end
    else
        protoRoll = rand();
        if protoRoll < 0.5
            protocol = 'TCP'; protocolCounts.TCP = protocolCounts.TCP + 1;
        elseif protoRoll < 0.8
            protocol = 'UDP'; protocolCounts.UDP = protocolCounts.UDP + 1;
        else
            protocol = 'ICMP'; protocolCounts.ICMP = protocolCounts.ICMP + 1;
        end
        fprintf(logFile,'%d,%d,192.168.1.%d,%s,%s,%s,%s,%d,%.2f,%d\n',...
            t, traffic, ip, regions{regionOf(ip)}, protocol, status, severity, health, mlScore, botSize);
    end

    pause(0.3);
end

% Close any attack segment still open at the end
if ~isnan(attackStartT)
    attackSegments(end+1,:) = [attackStartT, 50];
end

fclose(logFile);

%% FINAL REPORT (console)
accuracy  = (TP+TN) / max(1,(TP+TN+FP+FN)) * 100;
precision = TP / max(1,(TP+FP)) * 100;
recall    = TP / max(1,(TP+FN)) * 100;

accuracy2  = (TP2+TN2) / max(1,(TP2+TN2+FP2+FN2)) * 100;
precision2 = TP2 / max(1,(TP2+FP2)) * 100;
recall2    = TP2 / max(1,(TP2+FN2)) * 100;

attackTicks = botSizeHistory(botSizeHistory > 0);
if isempty(attackTicks)
    avgBotSize = 0; maxBotSize = 0;
else
    avgBotSize = mean(attackTicks);
    maxBotSize = max(attackTicks);
end

fprintf('\n');
fprintf('========================\n');
fprintf(' FINAL REPORT\n');
fprintf('========================\n');
fprintf('Normal Events     : %d\n', normalCount);
fprintf('Attack Events     : %d\n', attackCount);
fprintf('Blocked IPs       : %d\n', numel(blacklist));
fprintf('Peak Traffic      : %d pkt/s at t=%d\n', peakTraffic, peakTime);
fprintf('Attack Segments   : %d\n', size(attackSegments,1));
fprintf('Avg / Max Botnet  : %.1f / %d simultaneous attacker IPs\n', avgBotSize, maxBotSize);
fprintf('---- Rule-Based Detector (fixed threshold) ----\n');
fprintf('Accuracy  : %.1f%%\n', accuracy);
fprintf('Precision : %.1f%%\n', precision);
fprintf('Recall    : %.1f%%\n', recall);
fprintf('---- ML Detector (mini Isolation Forest) ----\n');
fprintf('Accuracy  : %.1f%%\n', accuracy2);
fprintf('Precision : %.1f%%\n', precision2);
fprintf('Recall    : %.1f%%\n', recall2);

%% EXPORT TEXT REPORT
reportFile = fopen('final_report.txt','w');
fprintf(reportFile, 'DDoS Detection Dashboard v3 - Final Report\n');
fprintf(reportFile, 'Generated: %s\n\n', datestr(now));
fprintf(reportFile, 'Normal Events     : %d\n', normalCount);
fprintf(reportFile, 'Attack Events     : %d\n', attackCount);
fprintf(reportFile, 'Blocked IPs       : %d\n', numel(blacklist));
fprintf(reportFile, 'Peak Traffic      : %d pkt/s at t=%d\n', peakTraffic, peakTime);
fprintf(reportFile, 'Avg / Max Botnet  : %.1f / %d simultaneous attacker IPs\n', avgBotSize, maxBotSize);
fprintf(reportFile, '\nRule-Based Detector:\n');
fprintf(reportFile, '  Accuracy  : %.1f%%\n', accuracy);
fprintf(reportFile, '  Precision : %.1f%%\n', precision);
fprintf(reportFile, '  Recall    : %.1f%%\n', recall);
fprintf(reportFile, '\nML Detector (mini Isolation Forest):\n');
fprintf(reportFile, '  Accuracy  : %.1f%%\n', accuracy2);
fprintf(reportFile, '  Precision : %.1f%%\n', precision2);
fprintf(reportFile, '  Recall    : %.1f%%\n', recall2);
fprintf(reportFile, '\nProtocol Distribution:\n');
fprintf(reportFile, 'TCP  : %d\n', protocolCounts.TCP);
fprintf(reportFile, 'UDP  : %d\n', protocolCounts.UDP);
fprintf(reportFile, 'ICMP : %d\n', protocolCounts.ICMP);
fprintf(reportFile, '\nAttack Origin by Region:\n');
for k = 1:numel(regions)
    fprintf(reportFile, '%-12s: %d offenses\n', regions{k}, regionOffenseCount(k));
end
fclose(reportFile);

%% PIE CHART - Traffic Distribution
figure('Name','Traffic Distribution');
pie([normalCount attackCount], {'Normal Traffic','Attack Traffic'});
title('Traffic Distribution');

%% PIE CHART - Protocol Distribution
figure('Name','Protocol Distribution');
pie([protocolCounts.TCP protocolCounts.UDP protocolCounts.ICMP], ...
    {'TCP','UDP','ICMP'});
title('Protocol Distribution');

%% BAR CHART - Detection Summary
figure('Name','Detection Summary');
bar([normalCount attackCount]);
set(gca,'XTickLabel',{'Normal','Attack'});
ylabel('Count');
title('Event Summary');
grid on;

%% BAR CHART - Top Offending IPs
figure('Name','Top Offending IPs');
[sortedCounts, sortedIdx] = sort(ipOffenseCount,'descend');
topN = 5;
topCounts = sortedCounts(1:topN);
topIPs = sortedIdx(1:topN);
labels = arrayfun(@(x) sprintf('192.168.1.%d', x), topIPs, 'UniformOutput', false);
bar(topCounts);
set(gca,'XTickLabel',labels,'XTickLabelRotation',30);
ylabel('Offense Count');
title('Top Offending Source IPs');
grid on;

%% BAR CHART - Attack Origin by Region
figure('Name','Attack Origin by Region');
bar(regionOffenseCount);
set(gca,'XTickLabel',regions,'XTickLabelRotation',20);
ylabel('Offense Count');
title('Simulated Attack Origin by Region');
grid on;

%% BAR CHART - Rule-based vs ML Detector Comparison
figure('Name','Detector Comparison');
compData = [accuracy precision recall; accuracy2 precision2 recall2];
bar(compData');
set(gca,'XTickLabel',{'Accuracy','Precision','Recall'});
legend({'Rule-Based','ML (Isolation Forest)'},'Location','southoutside','Orientation','horizontal');
ylabel('Percent (%)');
title('Rule-Based vs ML Detector Performance');
ylim([0 110]);
grid on;

%% MESSAGE BOX
if attackCount > 0
    msgbox(sprintf(['DDoS Attack Detected!\n' ...
        'Peak: %d pkt/s | Blocked IPs: %d\n' ...
        'Max Botnet Size: %d\n' ...
        'Rule-Based Accuracy: %.1f%%\n' ...
        'ML Accuracy: %.1f%%'], ...
        peakTraffic, numel(blacklist), maxBotSize, accuracy, accuracy2), 'Detection Result');
else
    msgbox('No Attack Detected','Detection Result');
end


%% =====================================================
%  LOCAL FUNCTIONS (mini Isolation Forest, no toolbox)
%% =====================================================

function score = isoForestScore(x, data, numTrees, sampleSize)
% Scores how anomalous point x is relative to recent history `data`,
% using a small from-scratch ensemble of random-split isolation trees.
% Score close to 1 -> anomaly, close to 0.5 -> typical, well below -> dense/normal.
    n = numel(data);
    sampleSize = min(sampleSize, n);
    if sampleSize < 2
        score = 0.5;
        return;
    end
    maxDepth = ceil(log2(max(2,sampleSize)));
    pathLengths = zeros(1,numTrees);
    for i = 1:numTrees
        idx = randperm(n, sampleSize);
        sample = data(idx);
        pathLengths(i) = isoTreeDepth(x, sample, 0, maxDepth);
    end
    avgPath = mean(pathLengths);
    c = cFactor(sampleSize);
    if c > 0
        score = 2^(-avgPath / c);
    else
        score = 0.5;
    end
end

function depth = isoTreeDepth(x, sample, currentDepth, maxDepth)
% Recursively partitions `sample` with random split points until x is
% isolated, max depth is hit, or the subset can't be split further.
    if currentDepth >= maxDepth || numel(sample) <= 1
        depth = currentDepth;
        return;
    end
    minV = min(sample);
    maxV = max(sample);
    if minV == maxV
        depth = currentDepth;
        return;
    end
    splitVal = minV + rand()*(maxV-minV);
    if x < splitVal
        subset = sample(sample < splitVal);
    else
        subset = sample(sample >= splitVal);
    end
    if isempty(subset)
        depth = currentDepth + 1;
        return;
    end
    depth = isoTreeDepth(x, subset, currentDepth+1, maxDepth);
end

function c = cFactor(n)
% Average path length of an unsuccessful search in a Binary Search Tree,
% used to normalize path lengths into a 0-1 anomaly score (Liu et al., 2008).
    if n <= 1
        c = 0;
    elseif n == 2
        c = 1;
    else
        c = 2*(log(n-1) + 0.5772156649) - (2*(n-1)/n);
    end
end
