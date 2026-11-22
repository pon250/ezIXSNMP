#requires -Version 5.1
# ============================================================
# ezIXSNMP 0.8.3  |  pon250.blogspot.com
#
# 対応検証機器: NEC IX2106
# 検証環境: Windows 11 / IX2106 Ver.10.9.35
# 未検証機種での動作は保証しません。
# ご利用は自己責任でお願いします。
#
# 改変・再配布は自由です。
# このスクリプトをベースにした派生版にも、オリジナル表記を残していただけるとうれしいです。
# ============================================================

# -------------------- User settings --------------------
$Language      = 0                 # 0: Japanese / 1: English
$RouterIP      = '192.168.1.254'
$Community     = 'IxMon_7aQ!29zR#'
$Interval      = 5                 # SNMP polling interval (seconds)
$HistoryPoints = 25
$InitialHeightRatio = 0.30         # Initial window height / screen height

# Interface indexes and OIDs inherited from the supplied monitor.ps1
$OID_TRAFFIC_IN4  = '1.3.6.1.2.1.31.1.1.1.6.405'
$OID_TRAFFIC_OUT4 = '1.3.6.1.2.1.31.1.1.1.10.405'
$OID_TRAFFIC_IN6  = '1.3.6.1.2.1.31.1.1.1.6.406'
$OID_TRAFFIC_OUT6 = '1.3.6.1.2.1.31.1.1.1.10.406'
$OID_NAPT         = '1.3.6.1.4.1.119.2.3.84.15.1.1.1.2.405'
$OID_TEMP         = '1.3.6.1.4.1.119.2.3.84.2.1.1.0'

$WeekDays = @(
    @('日','月','火','水','木','金','土'),
    @('SUN','MON','TUE','WED','THU','FRI','SAT')
)

$ErrorActionPreference = 'Stop'

# -------------------- OID BER bytes --------------------
$OidMap = @{
    $OID_TRAFFIC_IN4  = [byte[]]@(0x2B,0x06,0x01,0x02,0x01,0x1F,0x01,0x01,0x01,0x06,0x83,0x15)
    $OID_TRAFFIC_OUT4 = [byte[]]@(0x2B,0x06,0x01,0x02,0x01,0x1F,0x01,0x01,0x01,0x0A,0x83,0x15)
    $OID_TRAFFIC_IN6  = [byte[]]@(0x2B,0x06,0x01,0x02,0x01,0x1F,0x01,0x01,0x01,0x06,0x83,0x16)
    $OID_TRAFFIC_OUT6 = [byte[]]@(0x2B,0x06,0x01,0x02,0x01,0x1F,0x01,0x01,0x01,0x0A,0x83,0x16)
    $OID_NAPT         = [byte[]]@(0x2B,0x06,0x01,0x04,0x01,0x77,0x02,0x03,0x54,0x0F,0x01,0x01,0x01,0x02,0x83,0x15)
    $OID_TEMP         = [byte[]]@(0x2B,0x06,0x01,0x04,0x01,0x77,0x02,0x03,0x54,0x02,0x01,0x01,0x00)
}

function Read-Tlv([byte[]]$Data, [ref]$Offset) {
    if ($Offset.Value + 2 -gt $Data.Length) { throw 'Invalid BER response' }
    $tag = [int]$Data[$Offset.Value]; $Offset.Value++
    $first = [int]$Data[$Offset.Value]; $Offset.Value++
    if (($first -band 0x80) -eq 0) { $length = $first }
    else {
        $n = $first -band 0x7F
        if ($n -eq 0 -or $n -gt 4 -or $Offset.Value + $n -gt $Data.Length) { throw 'Invalid BER length' }
        $length = 0
        for ($i=0; $i -lt $n; $i++) { $length = ($length * 256) + [int]$Data[$Offset.Value]; $Offset.Value++ }
    }
    if ($length -lt 0 -or $Offset.Value + $length -gt $Data.Length) { throw 'BER length out of range' }
    $value = New-Object byte[] $length
    if ($length) { [Array]::Copy($Data,$Offset.Value,$value,0,$length) }
    $Offset.Value += $length
    return [pscustomobject]@{ Tag=$tag; Value=$value }
}

function Get-SnmpValue([string]$Oid) {
    $udp = $null
    try {
        if (-not $OidMap.ContainsKey($Oid)) { return $null }
        $oidBytes = $OidMap[$Oid]
        $communityBytes = [Text.Encoding]::ASCII.GetBytes($Community)
        $vb = [System.Collections.Generic.List[byte]]::new()
        $vb.Add(0x06); $vb.Add([byte]$oidBytes.Length); $vb.AddRange($oidBytes)
        $vb.Add(0x05); $vb.Add(0x00)
        $vbl = [System.Collections.Generic.List[byte]]::new(); $vbl.Add(0x30); $vbl.Add([byte]$vb.Count); $vbl.AddRange($vb)
        $pdu = [System.Collections.Generic.List[byte]]::new()
        $pdu.AddRange([byte[]]@(0x02,0x01,0x01,0x02,0x01,0x00,0x02,0x01,0x00))
        $pdu.Add(0x30); $pdu.Add([byte]$vbl.Count); $pdu.AddRange($vbl)
        $snmpPdu = [System.Collections.Generic.List[byte]]::new(); $snmpPdu.Add(0xA0); $snmpPdu.Add([byte]$pdu.Count); $snmpPdu.AddRange($pdu)
        $msg = [System.Collections.Generic.List[byte]]::new()
        $msg.AddRange([byte[]]@(0x02,0x01,0x01)); $msg.Add(0x04); $msg.Add([byte]$communityBytes.Length); $msg.AddRange($communityBytes); $msg.AddRange($snmpPdu)
        $packet = [System.Collections.Generic.List[byte]]::new(); $packet.Add(0x30); $packet.Add([byte]$msg.Count); $packet.AddRange($msg)
        $bytes = $packet.ToArray()
        $udp = [Net.Sockets.UdpClient]::new()
        $udp.Client.ReceiveTimeout = 1200; $udp.Client.SendTimeout = 1200
        $ep = [Net.IPEndPoint]::new([Net.IPAddress]::Parse($RouterIP),161)
        [void]$udp.Send($bytes,$bytes.Length,$ep)
        $remote = [Net.IPEndPoint]::new([Net.IPAddress]::Any,0)
        $response = $udp.Receive([ref]$remote)
        $o=0; $msgT=Read-Tlv $response ([ref]$o)
        $p=0; $null=Read-Tlv $msgT.Value ([ref]$p); $null=Read-Tlv $msgT.Value ([ref]$p)
        $respPdu=Read-Tlv $msgT.Value ([ref]$p)
        $q=0; $null=Read-Tlv $respPdu.Value ([ref]$q)
        $err=Read-Tlv $respPdu.Value ([ref]$q); $null=Read-Tlv $respPdu.Value ([ref]$q)
        $list=Read-Tlv $respPdu.Value ([ref]$q)
        $errValue=0; foreach($b in $err.Value){$errValue=($errValue*256)+[int]$b}
        if($errValue -ne 0){return $null}
        $r=0; $bind=Read-Tlv $list.Value ([ref]$r); $s=0
        $null=Read-Tlv $bind.Value ([ref]$s); $val=Read-Tlv $bind.Value ([ref]$s)
        if ($val.Tag -notin @(0x02,0x41,0x42,0x43,0x46)) { return $null }
        [long]$number=0; foreach($b in $val.Value){$number=($number*256)+[long]$b}
        return $number
    } catch { return $null }
    finally { if($null -ne $udp){$udp.Dispose()} }
}

# -------------------- Windows Forms / GDI+ --------------------
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing
[System.Windows.Forms.Application]::EnableVisualStyles()

# Hide the console window that may appear when this PS1 is launched by double-click.
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class HentekoNative {
    [DllImport("kernel32.dll")]
    public static extern IntPtr GetConsoleWindow();
    [DllImport("user32.dll")]
    public static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
}
'@

# Borderless form with native edge-resizing and drag-move hit testing.
Add-Type -ReferencedAssemblies @([System.Windows.Forms.Form].Assembly.Location, [System.Drawing.Point].Assembly.Location) -TypeDefinition @'
using System;
using System.Windows.Forms;
using System.Drawing;

public class HentekoWidgetForm : Form {
    private const int WM_NCHITTEST = 0x84;
    private const int HTCLIENT = 1;
    private const int HTCAPTION = 2;
    private const int HTLEFT = 10;
    private const int HTRIGHT = 11;
    private const int HTTOP = 12;
    private const int HTTOPLEFT = 13;
    private const int HTTOPRIGHT = 14;
    private const int HTBOTTOM = 15;
    private const int HTBOTTOMLEFT = 16;
    private const int HTBOTTOMRIGHT = 17;
    private const int Grip = 8;

    public HentekoWidgetForm() : base() {
        this.FormBorderStyle = FormBorderStyle.None;
        this.DoubleBuffered = true;
        this.SetStyle(ControlStyles.UserPaint |
                      ControlStyles.AllPaintingInWmPaint |
                      ControlStyles.OptimizedDoubleBuffer, true);
        this.UpdateStyles();
    }

    // Public property also makes the custom type's exposed surface explicit.
    public bool BufferedPaintingEnabled {
        get { return this.DoubleBuffered; }
    }

    protected override void WndProc(ref Message m) {
        if (m.Msg == WM_NCHITTEST) {
            base.WndProc(ref m);
            Point p = this.PointToClient(new Point(
                unchecked((short)((long)m.LParam & 0xffff)),
                unchecked((short)(((long)m.LParam >> 16) & 0xffff))));
            bool left = p.X < Grip;
            bool right = p.X >= this.ClientSize.Width - Grip;
            bool top = p.Y < Grip;
            bool bottom = p.Y >= this.ClientSize.Height - Grip;

            if (top && left) m.Result = (IntPtr)HTTOPLEFT;
            else if (top && right) m.Result = (IntPtr)HTTOPRIGHT;
            else if (bottom && left) m.Result = (IntPtr)HTBOTTOMLEFT;
            else if (bottom && right) m.Result = (IntPtr)HTBOTTOMRIGHT;
            else if (left) m.Result = (IntPtr)HTLEFT;
            else if (right) m.Result = (IntPtr)HTRIGHT;
            else if (top) m.Result = (IntPtr)HTTOP;
            else if (bottom) m.Result = (IntPtr)HTBOTTOM;
            else if (p.X >= this.ClientSize.Width - 44 && p.Y <= 42)
                m.Result = (IntPtr)HTCLIENT; // Keep the custom close button clickable.
            else if (p.X >= this.ClientSize.Width - 300 && p.Y >= this.ClientSize.Height - 30)
                m.Result = (IntPtr)HTCLIENT; // Keep the subtle footer link clickable.
            else
                m.Result = (IntPtr)HTCAPTION; // Drag anywhere else in the client area to move.
            return;
        }
        base.WndProc(ref m);
    }
}
'@

$consoleHandle = [HentekoNative]::GetConsoleWindow()
if ($consoleHandle -ne [IntPtr]::Zero) {
    [void][HentekoNative]::ShowWindow($consoleHandle, 0)
}

$script:history = [System.Collections.Generic.List[object]]::new()
$script:last = [ordered]@{ in4=0.0; out4=0.0; in6=0.0; out6=0.0; nat=0; temp=$null }
$script:trafficOK = $false
$script:natOK = $false
$script:previousCounters = $null
$script:previousAt = $null
$script:busy = $false

$form = [HentekoWidgetForm]::new()
$form.Text = ''
$form.FormBorderStyle = [Windows.Forms.FormBorderStyle]::None
$form.StartPosition = 'CenterScreen'
$form.BackColor = [Drawing.Color]::FromArgb(8,8,10)
$form.ForeColor = [Drawing.Color]::White
$form.MinimumSize = New-Object Drawing.Size(620,180)
$form.Width = [Math]::Max(760,[int]([Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Width * 0.65))
$form.Height = [Math]::Max(190,[int]([Windows.Forms.Screen]::PrimaryScreen.WorkingArea.Height * $InitialHeightRatio))
$form.MaximizeBox = $false
$form.ShowInTaskbar = $true
# DoubleBuffered is not publicly settable on Form in Windows PowerShell; leave default.

$timer = New-Object Windows.Forms.Timer
$timer.Interval = 1000
$script:nextPoll = [DateTime]::MinValue

function Draw-Text($g,[string]$text,[Drawing.Font]$font,[Drawing.Brush]$brush,[float]$x,[float]$y) {
    $g.DrawString($text,$font,$brush,$x,$y)
}
function Get-NiceMax([double[]]$values) {
    $m = 0.0
    foreach($v in $values){ if($v -gt $m){$m=$v} }
    if($m -le 0){return 1.0}
    # Keep the largest sample near 90% of the chart's vertical range.
    $raw=$m/0.90
    $power=[Math]::Pow(10,[Math]::Floor([Math]::Log10($raw)))
    $scaled=$raw/$power
    $step=if($scaled -le 1){1}elseif($scaled -le 2){2}elseif($scaled -le 5){5}else{10}
    return $step*$power
}
function Draw-Graph($g,[Drawing.Rectangle]$rect,[string]$title,[string]$statusColor,$series,[string]$valueText,[string]$displayMode='plain') {
    $bg=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(18,20,24)); $g.FillRectangle($bg,$rect); $bg.Dispose()
    $border=[Drawing.Pen]::new([Drawing.Color]::FromArgb(55,60,68),1); $g.DrawRectangle($border,$rect); $border.Dispose()
    $fTitle=[Drawing.Font]::new('Segoe UI',10,[Drawing.FontStyle]::Bold)
    $fontSize = 12.0
    $availableValueWidth = [Math]::Max(80, $rect.Width - 24)
    $fValue=[Drawing.Font]::new('Segoe UI',$fontSize,[Drawing.FontStyle]::Bold)
    $fTick=[Drawing.Font]::new('Segoe UI',10)
    $white=[Drawing.Brushes]::White
    Draw-Text $g $title $fTitle $white ($rect.X+12) ($rect.Y+8)
    if($displayMode -eq 'traffic') {
        # Center the two protocol groups, leaving a deliberate gap between v4 and v6.
        $parts = @(
            @{Text='v4'; Color=[Drawing.Color]::White},
            @{Text=('{0:0.00}' -f $script:last.in4); Color=[Drawing.Color]::FromArgb(255,140,0)},
            @{Text=('{0:0.00}' -f $script:last.out4); Color=[Drawing.Color]::FromArgb(255,104,0)},
            @{Text='v6'; Color=[Drawing.Color]::White},
            @{Text=('{0:0.00}' -f $script:last.in6); Color=[Drawing.Color]::FromArgb(0,204,255)},
            @{Text=('{0:0.00}' -f $script:last.out6); Color=[Drawing.Color]::FromArgb(0,102,153)}
        )
        $gapWidths = @(7,7,22,7,7)
        $partWidths = @($parts | ForEach-Object { $g.MeasureString($_.Text,$fValue).Width })
        $totalWidth = 0.0
        for($i=0;$i -lt $partWidths.Count;$i++){
            $totalWidth += $partWidths[$i]
            if($i -lt $gapWidths.Count){$totalWidth += $gapWidths[$i]}
        }
        $x = $rect.X + [Math]::Max(12,($rect.Width-$totalWidth)/2)
        for($i=0;$i -lt $parts.Count;$i++){
            $b=[Drawing.SolidBrush]::new($parts[$i].Color)
            $g.DrawString($parts[$i].Text,$fValue,$b,[single]$x,([single]($rect.Y+29)))
            $b.Dispose()
            $x += $partWidths[$i]
            if($i -lt $gapWidths.Count){$x += $gapWidths[$i]}
        }
    } else {
        $valueBrush=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(192,132,252))
        while($fValue.Size -gt 7 -and $g.MeasureString($valueText,$fValue).Width -gt ($rect.Width-24)){
            $fValue.Dispose(); $fontSize -= 0.5
            $fValue=[Drawing.Font]::new('Segoe UI',$fontSize,[Drawing.FontStyle]::Bold)
        }
        $valueWidth=$g.MeasureString($valueText,$fValue).Width
        $valueX=$rect.X+($rect.Width-$valueWidth)/2
        Draw-Text $g $valueText $fValue $valueBrush $valueX ($rect.Y+28)
        $valueBrush.Dispose()
    }
    $dotBrush=[Drawing.SolidBrush]::new([Drawing.Color]::FromName($statusColor))
    $g.FillEllipse($dotBrush,($rect.Right-23),($rect.Y+12),9,9); $dotBrush.Dispose()

    $left=$rect.X+58; $right=$rect.Right-14; $top=$rect.Y+65; $bottom=$rect.Bottom-24
    $allValues=@()
    foreach($s in $series){ $allValues += @($s.Values | ForEach-Object {[double]$_}) }
    $max=Get-NiceMax ([double[]]$allValues)
    $gridPen=[Drawing.Pen]::new([Drawing.Color]::FromArgb(48,54,62),1)
    $tickBrush=[Drawing.SolidBrush]::new([Drawing.Color]::Silver)
    for($i=0;$i -le 4;$i++){
        $y=$bottom-(($bottom-$top)*$i/4)
        $g.DrawLine($gridPen,$left,$y,$right,$y)
        $tick=($max*$i/4).ToString('0.##')
        $g.DrawString($tick,$fTick,$tickBrush,($rect.X+4),($y-8))
    }
    $gridPen.Dispose(); $tickBrush.Dispose()

    foreach($s in @($series)[2..3] + @($series)[0..1]){
        $values=@($s.Values)
        if($values.Count -gt 1){
            $pts=[Drawing.PointF[]]::new($values.Count)
            for($i=0;$i -lt $values.Count;$i++){
                $x=$left+(($right-$left)*$i/($values.Count-1))
                $y=$bottom-(($bottom-$top)*[Math]::Min($max,[Math]::Max(0,[double]$values[$i]))/$max)
                $pts[$i]=[Drawing.PointF]::new([single]$x,[single]$y)
            }
            $pen=[Drawing.Pen]::new($s.Color,2); $pen.LineJoin=[Drawing.Drawing2D.LineJoin]::Round
            $g.DrawLines($pen,$pts); $pen.Dispose()
        }
    }
    $fTitle.Dispose(); $fValue.Dispose(); $fTick.Dispose()
}

$script:closeHover = $false
$script:footerHover = $false
$form.Add_MouseMove({
    param($sender,$e)
    $hoverNow = ($e.X -ge ($form.ClientSize.Width-44) -and $e.Y -ge 0 -and $e.Y -le 42)
    if($hoverNow -ne $script:closeHover){$script:closeHover=$hoverNow; $form.Invalidate()}

    $footerText = 'pon250.blogspot.com   ezIXSNMP   0.8.3'
    $ff = [Drawing.Font]::new('Segoe UI', 8.5, [Drawing.FontStyle]::Regular)
    $measureBitmap = [Drawing.Bitmap]::new(1,1)
    $mg = [Drawing.Graphics]::FromImage($measureBitmap)
    $fs = $mg.MeasureString($footerText,$ff)
    $fx = [Math]::Max(12,$form.ClientSize.Width-$fs.Width-24)
    $fy = $form.ClientSize.Height-20
    $footerNow = ($e.X -ge $fx -and $e.X -le ($fx+$fs.Width) -and $e.Y -ge $fy -and $e.Y -le ($fy+$fs.Height))
    $mg.Dispose(); $measureBitmap.Dispose(); $ff.Dispose()
    if($footerNow -ne $script:footerHover){
        $script:footerHover=$footerNow
#        $form.Cursor = if($footerNow){[Windows.Forms.Cursors]::Hand}else{[Windows.Forms.Cursors]::Default}
    }
})
$form.Add_MouseLeave({
    if($script:closeHover){$script:closeHover=$false; $form.Invalidate()}
    $script:footerHover=$false
    $form.Cursor=[Windows.Forms.Cursors]::Default
})
$form.Add_MouseUp({
    param($sender,$e)
    if($e.Button -ne [Windows.Forms.MouseButtons]::Left){return}
    if($e.X -ge ($form.ClientSize.Width-44) -and $e.Y -le 42){$form.Close(); return}

    $footerText = 'pon250.blogspot.com   ezIXSNMP   0.8.3'
    $ff = [Drawing.Font]::new('Segoe UI', 8.5, [Drawing.FontStyle]::Regular)
    $measureBitmap = [Drawing.Bitmap]::new(1,1)
    $mg = [Drawing.Graphics]::FromImage($measureBitmap)
    $fs = $mg.MeasureString($footerText,$ff)
    $fx = [Math]::Max(12,$form.ClientSize.Width-$fs.Width-24)
    $fy = $form.ClientSize.Height-20
    $isFooter = ($e.X -ge $fx -and $e.X -le ($fx+$fs.Width) -and $e.Y -ge $fy -and $e.Y -le ($fy+$fs.Height))
    $mg.Dispose(); $measureBitmap.Dispose(); $ff.Dispose()
    if($isFooter){
        Start-Process 'https://pon250.blogspot.com/2026/11/nec-ix2106-snmp.html'
    }
})

$form.Add_Paint({
    param($sender,$e)
    $g=$e.Graphics
    $g.SmoothingMode=[Drawing.Drawing2D.SmoothingMode]::AntiAlias
    $g.Clear($form.BackColor)
    $w=$form.ClientSize.Width; $h=$form.ClientSize.Height
    $date=Get-Date
    $weekday=$WeekDays[$Language][$date.DayOfWeek.value__]
    $dateText=if($Language -eq 0){'{0:yyyy.MM.dd} ({1})' -f $date,$weekday}else{'{0:yyyy.MM.dd} ({1})' -f $date,$weekday}
    $fDate=[Drawing.Font]::new('Segoe UI',12,[Drawing.FontStyle]::Regular)
    $fClock=[Drawing.Font]::new('Segoe UI',22,[Drawing.FontStyle]::Bold)
    $fTemp=[Drawing.Font]::new('Segoe UI',15,[Drawing.FontStyle]::Bold)
    Draw-Text $g $dateText $fDate ([Drawing.Brushes]::Gainsboro) 18 10
    $clock=$date.ToString('HH:mm')
    $clockSize=$g.MeasureString($clock,$fClock)
    Draw-Text $g $clock $fClock ([Drawing.Brushes]::White) (($w-$clockSize.Width)/2) 4
    $tempText=if($null -ne $script:last.temp){('{0:0}C' -f $script:last.temp)}else{'--C'}
    $tempSize=$g.MeasureString($tempText,$fTemp)
    Draw-Text $g $tempText $fTemp ([Drawing.Brushes]::Gainsboro) ($w-$tempSize.Width-58) 9
    # Minimal Windows 11-inspired close glyph, drawn directly for consistent alignment.
    $closeRect=[Drawing.Rectangle]::new(($w-44),0,44,42)
    if($script:closeHover){
        $hoverBrush=[Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(48,210,215,225))
        $g.FillRectangle($hoverBrush,$closeRect); $hoverBrush.Dispose()
    }
    $closePen=[Drawing.Pen]::new([Drawing.Color]::FromArgb(245,245,247),2.0)
    $closePen.StartCap=[Drawing.Drawing2D.LineCap]::Round
    $closePen.EndCap=[Drawing.Drawing2D.LineCap]::Round
    $cx=$w-22; $cy=21; $half=5.5
    $g.DrawLine($closePen,[single]($cx-$half),[single]($cy-$half),[single]($cx+$half),[single]($cy+$half))
    $g.DrawLine($closePen,[single]($cx+$half),[single]($cy-$half),[single]($cx-$half),[single]($cy+$half))
    $closePen.Dispose()
    $fDate.Dispose(); $fClock.Dispose(); $fTemp.Dispose()
    $gap=12; $top=48; $bottomGap=28; $panelW=[int](($w-36-$gap)/2); $panelH=[Math]::Max(100,$h-$top-$bottomGap)
    $r1=[Drawing.Rectangle]::new(12,$top,$panelW,$panelH)
    $r2=[Drawing.Rectangle]::new((24+$panelW+$gap),$top,$panelW,$panelH)
    $v4d=@(); $v4u=@(); $v6d=@(); $v6u=@(); $nat=@()
    foreach($item in $script:history){
        $v4d += [double]$item.in4; $v4u += [double]$item.out4
        $v6d += [double]$item.in6; $v6u += [double]$item.out6
        $nat += [double]$item.nat
    }
    while($v4d.Count -lt $HistoryPoints){
        $v4d=@(0.0)+$v4d; $v4u=@(0.0)+$v4u; $v6d=@(0.0)+$v6d; $v6u=@(0.0)+$v6u; $nat=@(0.0)+$nat
    }
    $v4d=@($v4d | Select-Object -Last $HistoryPoints); $v4u=@($v4u | Select-Object -Last $HistoryPoints)
    $v6d=@($v6d | Select-Object -Last $HistoryPoints); $v6u=@($v6u | Select-Object -Last $HistoryPoints)
    $nat=@($nat | Select-Object -Last $HistoryPoints)
    $tStatus=if($script:trafficOK){'White'}else{'Orange'}
    $nStatus=if($script:natOK){'White'}else{'Orange'}
    $trafficLabel=''
    $trafficSeries=@(
        @{Values=$v4d; Color=[Drawing.Color]::FromArgb(255,140,0)},
        @{Values=$v4u; Color=[Drawing.Color]::FromArgb(255,104,0)},
        @{Values=$v6d; Color=[Drawing.Color]::FromArgb(0,204,255)},
        @{Values=$v6u; Color=[Drawing.Color]::FromArgb(0,102,153)}
    )
    $natSeries=@(@{Values=$nat; Color=[Drawing.Color]::FromArgb(192,132,252)})
    Draw-Graph $g $r1 'TRAFFIC (Down Up Mbps)' $tStatus $trafficSeries $trafficLabel 'traffic'
    Draw-Graph $g $r2 'NAT SESSIONS' $nStatus $natSeries ('{0:N0}' -f $script:last.nat) 'center'

    # Subtle three-stroke resize grip.
    $gripPen = [Drawing.Pen]::new([Drawing.Color]::FromArgb(115,150,155,165), 1.4)
    $gripPen.StartCap = [Drawing.Drawing2D.LineCap]::Round
    $gripPen.EndCap = [Drawing.Drawing2D.LineCap]::Round
    $gx = $w - 7
    $gy = $h - 7
    $g.DrawLine($gripPen, $gx-13, $gy,    $gx,    $gy-13)
    $g.DrawLine($gripPen, $gx-8,  $gy,    $gx,    $gy-8)
    $g.DrawLine($gripPen, $gx-3,  $gy,    $gx,    $gy-3)
    $gripPen.Dispose()

    # Small, low-contrast product signature at the bottom-right.
    # Keep clear of the resize grip.
    $footerText = 'pon250.blogspot.com   ezIXSNMP   0.8.3'
    $footerFont = [Drawing.Font]::new('Segoe UI', 8.5, [Drawing.FontStyle]::Regular)
    $footerBrush = [Drawing.SolidBrush]::new([Drawing.Color]::FromArgb(125,145,150,158))
    $footerSize = $g.MeasureString($footerText, $footerFont)
    $footerX = [Math]::Max(12, $w - $footerSize.Width - 24)
    $footerY = $h - 20
    $g.DrawString($footerText, $footerFont, $footerBrush, $footerX, $footerY)
    $footerFont.Dispose()
    $footerBrush.Dispose()
})

function Invoke-Poll {
    if($script:busy){return}; $script:busy=$true
    try {
        $now=[Diagnostics.Stopwatch]::GetTimestamp()
        $c=[ordered]@{
            in4=(Get-SnmpValue $OID_TRAFFIC_IN4); out4=(Get-SnmpValue $OID_TRAFFIC_OUT4)
            in6=(Get-SnmpValue $OID_TRAFFIC_IN6); out6=(Get-SnmpValue $OID_TRAFFIC_OUT6)
        }
        $napt=Get-SnmpValue $OID_NAPT
        $temp=Get-SnmpValue $OID_TEMP
        $trafficValid=@($c.Values | Where-Object {$null -eq $_}).Count -eq 0
        if($trafficValid){
            if($null -ne $script:previousCounters -and $null -ne $script:previousAt){
                $seconds=($now-$script:previousAt)/[double][Diagnostics.Stopwatch]::Frequency
                if($seconds -gt 0){
                    foreach($key in @('in4','out4','in6','out6')){
                        $diff=[double]$c[$key]-[double]$script:previousCounters[$key]
                        if($diff -lt 0){$diff=0}
                        $script:last[$key]=[Math]::Round(($diff*8/$seconds)/1000000,2)
                    }
                }
            }
            $script:previousCounters=$c; $script:previousAt=$now
        }
        $script:trafficOK=$trafficValid
        if($null -ne $napt){$script:last.nat=$napt; $script:natOK=$true}else{$script:natOK=$false}
        if($null -ne $temp){$script:last.temp=$temp}
        if($trafficValid -or $null -ne $napt){
            $script:history.Add([pscustomobject]@{in4=$script:last.in4;out4=$script:last.out4;in6=$script:last.in6;out6=$script:last.out6;nat=[double]$script:last.nat})
            while($script:history.Count -gt $HistoryPoints){$script:history.RemoveAt(0)}
        }
    } finally { $script:busy=$false; $form.Invalidate() }
}

$timer.Add_Tick({
    if((Get-Date) -ge $script:nextPoll){
        $script:nextPoll=(Get-Date).AddSeconds($Interval)
        Invoke-Poll
    }
    $form.Invalidate()
})
$form.Add_Shown({ Invoke-Poll; $script:nextPoll=(Get-Date).AddSeconds($Interval); $timer.Start() })
$form.Add_FormClosing({ $timer.Stop(); $timer.Dispose() })
[void]$form.ShowDialog()
